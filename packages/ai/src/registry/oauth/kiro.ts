import type { FetchImpl } from "../../types";
import { pollOAuthDeviceCodeFlow } from "./device-code";
import type { OAuthCredentials, OAuthLoginCallbacks } from "./types";

const BUILDER_ID_START_URL = "https://view.awsapps.com/start";
const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const SSO_SCOPES = [
	"codewhisperer:completions",
	"codewhisperer:analysis",
	"codewhisperer:conversations",
	"codewhisperer:transformations",
	"codewhisperer:taskassist",
];
const REGION_PROBES = [
	"us-east-1",
	"eu-west-1",
	"eu-central-1",
	"us-east-2",
	"eu-west-2",
	"eu-west-3",
	"eu-north-1",
	"ap-southeast-1",
	"ap-northeast-1",
	"us-west-2",
] as const;
const REQUEST_TIMEOUT_MS = 15_000;
const EXPIRY_SKEW_MS = 5 * 60 * 1000;

export type KiroCredentials = OAuthCredentials & {
	clientId: string;
	clientSecret: string;
	region: string;
	authMethod: "idc";
	profileArn?: string;
};

type DeviceAuthorization = {
	deviceCode: string;
	userCode: string;
	verificationUri: string;
	verificationUriComplete: string;
	interval: number;
	expiresIn: number;
};

type TokenResponse = {
	accessToken?: string;
	access_token?: string;
	refreshToken?: string;
	refresh_token?: string;
	expiresIn?: number;
	expires_in?: number;
	error?: string;
};

function withTimeout(signal: AbortSignal | undefined): AbortSignal {
	const timeout = AbortSignal.timeout(REQUEST_TIMEOUT_MS);
	return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

function field<T>(value: Record<string, unknown>, camel: string, snake: string): T | undefined {
	return (value[camel] ?? value[snake]) as T | undefined;
}

async function json<T>(response: Response): Promise<T> {
	try {
		return (await response.json()) as T;
	} catch {
		return {} as T;
	}
}

async function registerAndAuthorize(
	startUrl: string,
	region: string,
	fetchFn: FetchImpl,
	signal?: AbortSignal,
): Promise<{ clientId: string; clientSecret: string; device: DeviceAuthorization } | undefined> {
	const endpoint = `https://oidc.${region}.amazonaws.com`;
	const registered = await fetchFn(`${endpoint}/client/register`, {
		method: "POST",
		headers: { "Content-Type": "application/json", "User-Agent": "omp" },
		body: JSON.stringify({
			clientName: "omp",
			clientType: "public",
			scopes: SSO_SCOPES,
			grantTypes: [DEVICE_CODE_GRANT, "refresh_token"],
		}),
		signal: withTimeout(signal),
	});
	if (!registered.ok) return undefined;
	const registration = await json<Record<string, unknown>>(registered);
	const clientId = field<string>(registration, "clientId", "client_id");
	const clientSecret = field<string>(registration, "clientSecret", "client_secret");
	if (!clientId || !clientSecret) return undefined;

	const authorized = await fetchFn(`${endpoint}/device_authorization`, {
		method: "POST",
		headers: { "Content-Type": "application/json", "User-Agent": "omp" },
		body: JSON.stringify({ clientId, clientSecret, startUrl }),
		signal: withTimeout(signal),
	});
	if (!authorized.ok) return undefined;
	const raw = await json<Record<string, unknown>>(authorized);
	const deviceCode = field<string>(raw, "deviceCode", "device_code");
	const userCode = field<string>(raw, "userCode", "user_code");
	const verificationUri = field<string>(raw, "verificationUri", "verification_uri");
	const verificationUriComplete = field<string>(raw, "verificationUriComplete", "verification_uri_complete");
	const interval = Number(field<number | string>(raw, "interval", "interval") ?? 5);
	const expiresIn = Number(field<number | string>(raw, "expiresIn", "expires_in") ?? 600);
	if (
		!deviceCode ||
		!userCode ||
		!verificationUri ||
		!verificationUriComplete ||
		!Number.isFinite(interval) ||
		!Number.isFinite(expiresIn)
	) {
		return undefined;
	}
	return {
		clientId,
		clientSecret,
		device: {
			deviceCode,
			userCode,
			verificationUri,
			verificationUriComplete,
			interval: Math.max(1, interval),
			expiresIn: Math.max(1, expiresIn),
		},
	};
}

async function beginDeviceAuthorization(
	startUrl: string,
	preferredRegion: string | undefined,
	fetchFn: FetchImpl,
	signal?: AbortSignal,
): Promise<{ region: string; clientId: string; clientSecret: string; device: DeviceAuthorization }> {
	const regions = preferredRegion ? [preferredRegion] : [...REGION_PROBES];
	for (const region of regions) {
		try {
			const result = await registerAndAuthorize(startUrl, region, fetchFn, signal);
			if (result) return { region, ...result };
		} catch (error) {
			if (signal?.aborted) throw error;
		}
	}
	throw new Error("Could not find an AWS Identity Center region for the supplied Kiro start URL");
}

async function pollToken(
	flow: { region: string; clientId: string; clientSecret: string; device: DeviceAuthorization },
	fetchFn: FetchImpl,
	signal?: AbortSignal,
): Promise<KiroCredentials> {
	return pollOAuthDeviceCodeFlow<KiroCredentials>({
		intervalSeconds: flow.device.interval,
		expiresInSeconds: flow.device.expiresIn,
		signal,
		poll: async () => {
			const response = await fetchFn(`https://oidc.${flow.region}.amazonaws.com/token`, {
				method: "POST",
				headers: { "Content-Type": "application/json", "User-Agent": "omp" },
				body: JSON.stringify({
					clientId: flow.clientId,
					clientSecret: flow.clientSecret,
					deviceCode: flow.device.deviceCode,
					grantType: DEVICE_CODE_GRANT,
				}),
				signal: withTimeout(signal),
			});
			const data = await json<TokenResponse>(response);
			if (response.ok && !data.error) {
				const access = data.accessToken ?? data.access_token;
				const refresh = data.refreshToken ?? data.refresh_token;
				const expiresIn = Number(data.expiresIn ?? data.expires_in);
				if (!access || !refresh || !Number.isFinite(expiresIn)) {
					return { status: "failed", message: "Kiro token response was missing required fields" };
				}
				return {
					status: "complete",
					value: {
						access,
						refresh: `${refresh}|${flow.clientId}|${flow.clientSecret}|idc|${flow.region}`,
						expires: Date.now() + expiresIn * 1000 - EXPIRY_SKEW_MS,
						clientId: flow.clientId,
						clientSecret: flow.clientSecret,
						region: flow.region,
						authMethod: "idc",
					},
				};
			}
			if (data.error === "authorization_pending") return { status: "pending" };
			if (data.error === "slow_down") return { status: "slow_down" };
			return {
				status: "failed",
				message: `Kiro authorization failed${data.error ? `: ${data.error}` : ` (HTTP ${response.status})`}`,
			};
		},
	});
}

export async function loginKiro(callbacks: OAuthLoginCallbacks): Promise<KiroCredentials> {
	const startUrlInput =
		(
			await callbacks.onPrompt({
				message: "Paste your IAM Identity Center start URL, or leave blank for AWS Builder ID",
				placeholder: BUILDER_ID_START_URL,
				allowEmpty: true,
			})
		)?.trim() ?? "";
	if (callbacks.signal?.aborted) throw new Error("Login cancelled");
	const startUrl = startUrlInput || BUILDER_ID_START_URL;
	if (!/^https?:\/\//i.test(startUrl)) throw new Error("Kiro start URL must be an http(s) URL");

	let preferredRegion: string | undefined;
	if (startUrl !== BUILDER_ID_START_URL) {
		preferredRegion =
			(
				(await callbacks.onPrompt({
					message: "AWS Identity Center region (blank to auto-detect)",
					placeholder: "us-east-1",
				})) ?? ""
			).trim() || undefined;
	}
	const fetchFn = callbacks.fetch ?? fetch;
	const flow = await beginDeviceAuthorization(startUrl, preferredRegion, fetchFn, callbacks.signal);
	callbacks.onAuth({
		url: flow.device.verificationUriComplete,
		instructions: `Open ${flow.device.verificationUri} and enter your code: ${flow.device.userCode}`,
	});
	callbacks.onProgress?.(`Waiting for Kiro authorization in ${flow.region}...`);
	return pollToken(flow, fetchFn, callbacks.signal);
}

function parseRefreshMetadata(credentials: OAuthCredentials): {
	token: string;
	clientId: string;
	clientSecret: string;
	region: string;
} {
	const kiro = credentials as KiroCredentials;
	const parts = credentials.refresh.split("|");
	const token = parts[0];
	const clientId = kiro.clientId ?? parts[1];
	const clientSecret = kiro.clientSecret ?? parts[2];
	const region = kiro.region ?? (parts[3] === "idc" ? parts[4] : undefined);
	if (!token || !clientId || !clientSecret || !region) {
		throw new Error("Kiro OAuth credential is missing Identity Center refresh metadata; run /login kiro again");
	}
	return { token, clientId, clientSecret, region };
}

export async function refreshKiroToken(credentials: OAuthCredentials): Promise<KiroCredentials> {
	const { token, clientId, clientSecret, region } = parseRefreshMetadata(credentials);
	const response = await fetch(`https://oidc.${region}.amazonaws.com/token`, {
		method: "POST",
		headers: { "Content-Type": "application/json", "User-Agent": "omp" },
		body: JSON.stringify({ clientId, clientSecret, refreshToken: token, grantType: "refresh_token" }),
		signal: withTimeout(undefined),
	});
	const data = await json<TokenResponse>(response);
	if (!response.ok) throw new Error(`Kiro token refresh failed (HTTP ${response.status})`);
	const access = data.accessToken ?? data.access_token;
	const refresh = data.refreshToken ?? data.refresh_token ?? token;
	const expiresIn = Number(data.expiresIn ?? data.expires_in);
	if (!access || !Number.isFinite(expiresIn))
		throw new Error("Kiro token refresh response was missing required fields");
	return {
		access,
		refresh: `${refresh}|${clientId}|${clientSecret}|idc|${region}`,
		expires: Date.now() + expiresIn * 1000 - EXPIRY_SKEW_MS,
		clientId,
		clientSecret,
		region,
		authMethod: "idc",
		profileArn: (credentials as KiroCredentials).profileArn,
	};
}

export function getKiroApiKey(credentials: OAuthCredentials): string {
	const kiro = credentials as KiroCredentials;
	return JSON.stringify({ token: credentials.access, region: kiro.region, profileArn: kiro.profileArn });
}

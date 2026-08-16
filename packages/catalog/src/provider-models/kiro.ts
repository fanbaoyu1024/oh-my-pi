import type { Effort } from "../effort";
import { Effort as EffortValue } from "../effort";
import type { FetchImpl, Model, ModelSpec, ThinkingConfig } from "../types";

const API_REGION_MAP: Record<string, string> = {
	"us-west-1": "us-east-1",
	"us-west-2": "us-east-1",
	"us-east-2": "us-east-1",
	"ap-southeast-1": "us-east-1",
	"ap-southeast-2": "us-east-1",
	"ap-northeast-1": "us-east-1",
	"ap-south-1": "us-east-1",
	"eu-west-1": "eu-central-1",
	"eu-west-2": "eu-central-1",
	"eu-west-3": "eu-central-1",
	"eu-north-1": "eu-central-1",
	"eu-south-1": "eu-central-1",
	"eu-south-2": "eu-central-1",
	"eu-central-2": "eu-central-1",
};

export const KIRO_API = "kiro-api" as const;

export interface KiroEndpoints {
	region: string;
	management: string;
	runtime: string;
}

export function resolveKiroApiRegion(ssoRegion?: string): string {
	const normalized = ssoRegion?.trim();
	return normalized ? (API_REGION_MAP[normalized] ?? normalized) : "us-east-1";
}

export function getKiroEndpoints(region: string): KiroEndpoints {
	return {
		region,
		management: `https://management.${region}.kiro.dev/`,
		runtime: `https://runtime.${region}.kiro.dev/`,
	};
}

export function getKiroRegionFromEndpoint(endpoint: string | undefined): string | undefined {
	if (!endpoint) return undefined;
	try {
		const [service, region, ...suffix] = new URL(endpoint).hostname.split(".");
		if ((service === "management" || service === "runtime") && suffix.join(".") === "kiro.dev") return region;
	} catch {
		// A custom or incomplete base URL is handled by the default region.
	}
	return undefined;
}

export interface KiroCatalogModel {
	modelId: string;
	displayName?: string;
	tokenLimits?: {
		maxInputTokens?: number;
		maxOutputTokens?: number;
		[key: string]: unknown;
	};
	additionalModelRequestFieldsSchema?: Record<string, unknown> | null;
	[key: string]: unknown;
}

export interface KiroListAvailableModelsResponse {
	models: KiroCatalogModel[];
	[key: string]: unknown;
}

export type KiroModelSpec = ModelSpec<typeof KIRO_API> & {
	kiroModelId?: string;
	kiroRegion?: string;
	kiroProfileArn?: string;
	additionalModelRequestFieldsSchema?: Record<string, unknown>;
};

export type KiroModel = Model<typeof KIRO_API> & {
	kiroModelId?: string;
	kiroRegion?: string;
	kiroProfileArn?: string;
	additionalModelRequestFieldsSchema?: Record<string, unknown>;
};

export class KiroManagementHttpError extends Error {
	readonly status: number;

	constructor(operation: string, region: string, status: number) {
		super(`Kiro management ${operation} failed in ${region}: HTTP ${status}`);
		this.name = "KiroManagementHttpError";
		this.status = status;
	}
}

async function managementRequest<TResponse>(
	auth: { accessToken: string; region: string },
	operation: string,
	path: string,
	method: "GET" | "POST",
	params: Record<string, string | undefined>,
	fetchFn: FetchImpl,
	signal?: AbortSignal,
): Promise<TResponse> {
	const url = new URL(path, getKiroEndpoints(auth.region).management);
	const headers: Record<string, string> = {
		Accept: "application/json",
		Authorization: `Bearer ${auth.accessToken}`,
	};
	const request: RequestInit = { method, headers, signal };
	if (method === "GET") {
		for (const [name, value] of Object.entries(params)) {
			if (value !== undefined) url.searchParams.set(name, value);
		}
	} else {
		headers["Content-Type"] = "application/json";
		request.body = JSON.stringify(
			Object.fromEntries(Object.entries(params).filter(([, value]) => value !== undefined)),
		);
	}

	let response: Response;
	try {
		response = await fetchFn(url, request);
	} catch (error) {
		if (signal?.aborted) throw error;
		throw new Error(`Kiro management ${operation} request failed in ${auth.region}`, { cause: error });
	}
	if (!response.ok) throw new KiroManagementHttpError(operation, auth.region, response.status);
	try {
		return (await response.json()) as TResponse;
	} catch (error) {
		throw new Error(`Kiro management ${operation} returned invalid JSON in ${auth.region}`, { cause: error });
	}
}

export async function resolveKiroProfileArn(
	auth: { accessToken: string; region: string },
	providedProfileArn: string | undefined,
	fetchFn: FetchImpl = globalThis.fetch,
	signal?: AbortSignal,
): Promise<string> {
	if (providedProfileArn) return providedProfileArn;
	const response = await managementRequest<{ profiles?: Array<{ arn?: string }> }>(
		auth,
		"ListAvailableProfiles",
		"List-Available-Profiles",
		"POST",
		{},
		fetchFn,
		signal,
	);
	const profileArn = response.profiles?.find(
		profile => typeof profile.arn === "string" && profile.arn.length > 0,
	)?.arn;
	if (!profileArn) throw new Error(`Kiro management ListAvailableProfiles returned no profile in ${auth.region}`);
	return profileArn;
}

export async function fetchKiroModelCatalog(
	auth: { accessToken: string; region: string },
	providedProfileArn?: string,
	fetchFn: FetchImpl = globalThis.fetch,
	signal?: AbortSignal,
): Promise<{ profileArn: string; response: KiroListAvailableModelsResponse }> {
	const profileArn = await resolveKiroProfileArn(auth, providedProfileArn, fetchFn, signal);
	const response = await managementRequest<KiroListAvailableModelsResponse>(
		auth,
		"ListAvailableModels",
		"List-Available-Models",
		"GET",
		{ origin: "KIRO_CLI", profileArn },
		fetchFn,
		signal,
	);
	if (!Array.isArray(response.models) || response.models.length === 0) {
		throw new Error(`Kiro management ListAvailableModels returned no models in ${auth.region}`);
	}
	if (response.models.some(model => !model || typeof model.modelId !== "string" || model.modelId.length === 0)) {
		throw new Error(`Kiro management ListAvailableModels returned an invalid catalog in ${auth.region}`);
	}
	return { profileArn, response };
}

const ZERO_COST = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 } as const;
const DEFAULT_CONTEXT_WINDOW = 200_000;
const DEFAULT_MAX_TOKENS = 8_192;
const KIRO_RUNTIME = getKiroEndpoints("us-east-1").runtime;
const KIRO_THINKING: ThinkingConfig = {
	mode: "effort",
	efforts: [
		EffortValue.Low,
		EffortValue.Medium,
		EffortValue.High,
		EffortValue.XHigh,
		EffortValue.Max,
	] as readonly Effort[],
	defaultLevel: EffortValue.High,
};

function isReasoningModel(id: string): boolean {
	return /auto|claude-opus|claude-sonnet|deepseek|gpt|glm|qwen/i.test(id);
}

function createBootstrapModel(
	id: string,
	options: Partial<Pick<KiroModelSpec, "reasoning" | "input" | "contextWindow" | "maxTokens" | "thinking">> = {},
): KiroModelSpec {
	return {
		id,
		name: id
			.split("-")
			.map(part => part.charAt(0).toUpperCase() + part.slice(1))
			.join(" "),
		api: KIRO_API,
		provider: "kiro",
		baseUrl: KIRO_RUNTIME,
		reasoning: options.reasoning ?? isReasoningModel(id),
		input: options.input ?? (/^(auto|claude)/i.test(id) ? ["text", "image"] : ["text"]),
		supportsTools: true,
		cost: { ...ZERO_COST },
		contextWindow: options.contextWindow ?? DEFAULT_CONTEXT_WINDOW,
		maxTokens: options.maxTokens ?? DEFAULT_MAX_TOKENS,
		...(options.thinking ? { thinking: options.thinking } : {}),
		kiroModelId: id,
	};
}

/** Safe offline bootstrap; authenticated discovery replaces it with the profile catalog. */
export const KIRO_MODELS: readonly KiroModelSpec[] = [
	createBootstrapModel("auto", { contextWindow: 1_000_000, maxTokens: 65_536, thinking: KIRO_THINKING }),
	createBootstrapModel("claude-opus-5", { contextWindow: 1_000_000, maxTokens: 128_000, thinking: KIRO_THINKING }),
	createBootstrapModel("claude-sonnet-5", { contextWindow: 1_000_000, maxTokens: 65_536, thinking: KIRO_THINKING }),
	createBootstrapModel("claude-opus-4.8", { contextWindow: 1_000_000, maxTokens: 128_000, thinking: KIRO_THINKING }),
	createBootstrapModel("claude-opus-4.7", { contextWindow: 1_000_000, maxTokens: 128_000, thinking: KIRO_THINKING }),
	createBootstrapModel("claude-opus-4.6", { maxTokens: 32_768, thinking: KIRO_THINKING }),
	createBootstrapModel("claude-sonnet-4.6", { maxTokens: 65_536, thinking: KIRO_THINKING }),
	createBootstrapModel("claude-opus-4.5", { maxTokens: 65_536, thinking: KIRO_THINKING }),
	createBootstrapModel("claude-sonnet-4.5", { maxTokens: 65_536, thinking: KIRO_THINKING }),
	createBootstrapModel("claude-sonnet-4", { maxTokens: 65_536, thinking: KIRO_THINKING }),
	createBootstrapModel("claude-haiku-4.5", { reasoning: false, maxTokens: 65_536 }),
	createBootstrapModel("gpt-5.6-sol", { thinking: KIRO_THINKING }),
	createBootstrapModel("gpt-5.6-terra", { thinking: KIRO_THINKING }),
	createBootstrapModel("gpt-5.6-luna", { thinking: KIRO_THINKING }),
	createBootstrapModel("deepseek-3.2", { thinking: KIRO_THINKING }),
	createBootstrapModel("minimax-m2.5", { reasoning: false }),
	createBootstrapModel("minimax-m2.1", { reasoning: false }),
	createBootstrapModel("glm-5", { thinking: KIRO_THINKING }),
	createBootstrapModel("qwen3-coder-next", { thinking: KIRO_THINKING }),
];

function dynamicThinking(schema: Record<string, unknown> | null | undefined): ThinkingConfig | undefined {
	return schema ? KIRO_THINKING : undefined;
}

export function mapKiroCatalogToModelSpecs(catalog: readonly KiroCatalogModel[], region: string): KiroModelSpec[] {
	const seen = new Set<string>();
	return catalog.map(model => {
		const id = model.modelId.trim();
		if (!id || seen.has(id)) throw new Error(`Kiro management catalog contains duplicate model ID ${id}`);
		seen.add(id);
		const existing = KIRO_MODELS.find(candidate => candidate.kiroModelId === id || candidate.id === id);
		const limits = model.tokenLimits;
		const schema = model.additionalModelRequestFieldsSchema;
		return {
			...(existing ?? createBootstrapModel(id)),
			id,
			name: model.displayName?.trim() || existing?.name || id,
			api: KIRO_API,
			provider: "kiro",
			baseUrl: getKiroEndpoints(region).runtime,
			reasoning: schema !== undefined ? true : (existing?.reasoning ?? isReasoningModel(id)),
			contextWindow: limits?.maxInputTokens ?? existing?.contextWindow ?? DEFAULT_CONTEXT_WINDOW,
			maxTokens: limits?.maxOutputTokens ?? existing?.maxTokens ?? DEFAULT_MAX_TOKENS,
			supportsTools: true,
			kiroModelId: id,
			kiroRegion: region,
			...(schema ? { additionalModelRequestFieldsSchema: schema, thinking: dynamicThinking(schema) } : {}),
		};
	});
}

export function parseKiroApiKey(value: string | undefined): {
	token: string;
	region?: string;
	profileArn?: string;
} {
	if (!value?.startsWith("{")) return { token: value ?? "" };
	try {
		const parsed = JSON.parse(value) as { token?: unknown; region?: unknown; profileArn?: unknown };
		if (typeof parsed.token === "string" && parsed.token.length > 0) {
			return {
				token: parsed.token,
				region: typeof parsed.region === "string" ? parsed.region : undefined,
				profileArn: typeof parsed.profileArn === "string" ? parsed.profileArn : undefined,
			};
		}
	} catch {
		// Treat malformed structured values as raw bearer values for compatibility.
	}
	return { token: value };
}

export function kiroCacheProviderId(apiKey: string | undefined, baseUrl?: string): string {
	const parsed = parseKiroApiKey(apiKey);
	const region = resolveKiroApiRegion(parsed.region ?? getKiroRegionFromEndpoint(baseUrl));
	const profileFingerprint = parsed.profileArn ? Bun.hash(parsed.profileArn).toString(36) : "default";
	return `kiro:${region}:${profileFingerprint}`;
}

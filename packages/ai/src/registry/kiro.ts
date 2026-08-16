import type { OAuthCredentials, OAuthLoginCallbacks } from "./oauth/types";
import type { ProviderDefinition } from "./types";

export const kiroProvider = {
	id: "kiro",
	name: "Kiro (AWS Builder ID / IAM Identity Center)",
	login: async (cb: OAuthLoginCallbacks) => {
		const { loginKiro } = await import("./oauth/kiro");
		return loginKiro(cb);
	},
	refreshToken: async (credentials: OAuthCredentials) => {
		const { refreshKiroToken } = await import("./oauth/kiro");
		return refreshKiroToken(credentials);
	},
	getApiKey: (credentials: OAuthCredentials) => {
		const kiro = credentials as OAuthCredentials & { region?: string; profileArn?: string };
		return JSON.stringify({ token: credentials.access, region: kiro.region, profileArn: kiro.profileArn });
	},
} as const satisfies ProviderDefinition;

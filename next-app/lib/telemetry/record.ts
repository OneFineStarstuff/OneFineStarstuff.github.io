export type ProviderMeta = { provider?: string; model?: string; layer?: string; version?: string; tokensIn?: number; tokensOut?: number; latencyMs?: number; tools?: unknown[] };
export function recordProviderInvocation(sessionId: string | undefined, meta: ProviderMeta) {
  // Placeholder: in MVP, just log to console; integrate with OTel/PostHog later
  console.log('provider_invocation', { sessionId, ...meta });
}

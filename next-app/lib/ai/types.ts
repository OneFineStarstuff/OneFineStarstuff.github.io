export type ModelConfig = { temperature?: number; maxTokens?: number };
export type StreamChunk = { id?: string; delta: string; done?: boolean };
export type ProviderMeta = { name?: string; model?: string; layer?: 'surface' | 'depth'; version?: string; tokensIn?: number; tokensOut?: number; latencyMs?: number };
export interface ModelResponse { text?: string; chunks?: AsyncIterable<StreamChunk>; meta: ProviderMeta }
export interface ModelProvider { id: string; supportsStreaming: boolean; invoke(prompt: string): Promise<ModelResponse>; stream(prompt: string): Promise<ModelResponse> }

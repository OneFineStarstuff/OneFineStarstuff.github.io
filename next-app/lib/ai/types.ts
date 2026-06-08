export type ModelConfig = { temperature?: number; maxTokens?: number };
export type StreamChunk = { id?: string; delta: string; done?: boolean };

export type FairnessMetrics = {
  demographicParity: number;
  isFair: boolean;
  threshold: number;
};

export type CAEMetadata = {
  attribution: string;
  confidence: number;
  context: string;
};

export type ProviderMeta = {
  name?: string;
  model?: string;
  layer?: 'surface' | 'depth';
  version?: string;
  tokensIn?: number;
  tokensOut?: number;
  latencyMs?: number;
  fairness?: FairnessMetrics;
  cae?: CAEMetadata;
};

export interface ModelResponse {
  text?: string;
  chunks?: AsyncIterable<StreamChunk>;
  meta: ProviderMeta;
}

export interface ModelProvider {
  id: string;
  supportsStreaming: boolean;
  invoke(prompt: string): Promise<ModelResponse>;
  stream(prompt: string): Promise<ModelResponse>;
}

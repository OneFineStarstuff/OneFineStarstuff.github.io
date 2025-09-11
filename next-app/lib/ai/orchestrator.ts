import { CircuitBreaker } from './circuitBreaker';
import type { ModelProvider, ModelResponse } from './types';

type Intent = 'casual' | 'actionable' | 'analytical' | 'sensitive';
export type RouteDecision = { intent: Intent; target: 'surface' | 'depth'; reason: string };

export class Orchestrator {
  private breakerDepth = new CircuitBreaker(3, 15000);
  constructor(private surface: ModelProvider, private depth: ModelProvider, private intentDetect: (msg: string) => Intent) {}

  route(input: string, override?: 'surface' | 'depth'): RouteDecision {
    if (override) return { intent: this.intentDetect(input), target: override, reason: 'user_override' };
    const intent = this.intentDetect(input);
    const target = intent === 'analytical' ? 'depth' : 'surface';
    return { intent, target, reason: 'policy' };
  }

  async respond(input: string, stream = true): Promise<ModelResponse> {
    const decision = this.route(input);
    const primary = decision.target === 'depth' ? this.depth : this.surface;
    const fallback = decision.target === 'depth' ? this.surface : this.depth;

    if (decision.target === 'depth' && !this.breakerDepth.canPass()) {
      return this.surface.invoke(this.decorate(input, { fallback: 'depth_breaker_open' }));
    }

    try {
      const res = stream && primary.supportsStreaming
        ? await primary.stream(this.decorate(input, decision))
        : await primary.invoke(this.decorate(input, decision));
      if (decision.target === 'depth') this.breakerDepth.recordSuccess();
      return res;
    } catch (e) {
      if (decision.target === 'depth') this.breakerDepth.recordFailure();
      return fallback.invoke(this.decorate(input, { fallback: 'primary_failed' }));
    }
  }

  private decorate(input: string, meta: Record<string, unknown>): string {
    return `<!-- orchestration:${JSON.stringify(meta)} -->\n${input}`;
  }
}

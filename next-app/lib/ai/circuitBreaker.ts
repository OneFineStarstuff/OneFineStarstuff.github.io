type State = 'closed' | 'open' | 'half-open';
export class CircuitBreaker {
  private failures = 0; private state: State = 'closed'; private openedAt = 0;
  constructor(private failureThreshold = 3, private recoveryMs = 15000) {}
  canPass(): boolean {
    if (this.state === 'open' && Date.now() - this.openedAt > this.recoveryMs) { this.state = 'half-open'; return true; }
    return this.state !== 'open';
  }
  recordSuccess() { this.failures = 0; this.state = 'closed'; }
  recordFailure() { this.failures++; if (this.failures >= this.failureThreshold) { this.state = 'open'; this.openedAt = Date.now(); } }
  isOpen() { return this.state === 'open'; }
}

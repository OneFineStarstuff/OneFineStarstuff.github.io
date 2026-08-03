export type ModerationAction = 'allow' | 'block' | 'revise';
export type ModerationEvent = { stage: 'pre' | 'post'; action: ModerationAction; reason?: string };

const SENSITIVE = /(ssn|password|credit\s*card|cvv)/i;

export function preFilter(input: string): ModerationEvent {
  if (SENSITIVE.test(input)) return { stage: 'pre', action: 'revise', reason: 'redact_sensitive' };
  return { stage: 'pre', action: 'allow' };
}

export function steerPrompt(input: string): string {
  return `Policy: Be safe and helpful. Avoid unsafe advice.\n${input}`;
}

export function postModerate(output: string): ModerationEvent {
  if (/violent|illegal/i.test(output)) return { stage: 'post', action: 'block', reason: 'unsafe_content' };
  return { stage: 'post', action: 'allow' };
}

export type ChangeSignals = {
  changesPurpose?: boolean;
  changesModel?: boolean;
  changesDataProcessing?: boolean;
  changesSecurityBoundary?: boolean;
  changesCriticalSafetyControl?: boolean;
  operationalImpact?: boolean;
};

export type ChangeClass = 0 | 1 | 2 | 3;

export function classifyChange(signals: ChangeSignals): {
  classification: ChangeClass;
  label: string;
  reasons: string[];
} {
  const material = [
    ["changesPurpose", "intended purpose changed"],
    ["changesModel", "model or model behavior changed"],
    ["changesDataProcessing", "personal or sensitive-data processing changed"],
    ["changesSecurityBoundary", "security or privilege boundary changed"],
    ["changesCriticalSafetyControl", "critical safety/control logic changed"],
  ] as const;
  const reasons = material.filter(([key]) => signals[key] === true).map(([, reason]) => reason);
  if (reasons.length > 0) return { classification: 3, label: "MATERIAL", reasons };
  if (signals.operationalImpact) return { classification: 2, label: "SIGNIFICANT", reasons: ["operational impact declared"] };
  return { classification: 1, label: "NON_MATERIAL", reasons: ["no material or significant impact signal declared"] };
}

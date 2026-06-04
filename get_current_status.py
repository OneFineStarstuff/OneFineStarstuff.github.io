import random
from datetime import datetime, timezone
from omni_sentinel_cli import PhaseState, TelemetrySnapshot
from omni_sentinel_24h_monitor import GSRIEngine, HardwareAttestation

gsri_engine = GSRIEngine()
attestation = HardwareAttestation()
timestamp = datetime.now(timezone.utc)
telemetry = TelemetrySnapshot(
    timestamp=timestamp.timestamp(),
    cpu_percent=random.uniform(10, 80),
    memory_available_gb=random.uniform(8, 64),
    latency_ms=random.uniform(10, 600),
    latency_blocks=0,
    region="ALBION_PROTOCOL",
    phase=PhaseState.MONITORING.value,
)
telemetry.latency_blocks = int(telemetry.latency_ms / 20)
g_sri = gsri_engine.calculate(telemetry)
attested = attestation.verify()

print(f"G-SRI: {g_sri}")
print(f"TPM Status: {'PCR_MATCH=TRUE' if attested else 'PCR_MATCH=FALSE'}")
print(f"Latency: {telemetry.latency_ms}ms")

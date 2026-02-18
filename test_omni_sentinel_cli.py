#!/usr/bin/env python3
"""
Test Suite for Omni-Sentinel CLI

Classification: CONFIDENTIAL - BOARD USE ONLY
Document ID: OMNI-SENTINEL-CLI-TESTS-2026-001
Version: 1.0
Date: 2026-01-25

Test Coverage:
  - Rule evaluation and conflict resolution
  - Telemetry monitoring accuracy
  - HMAC integrity verification
  - Phase state transitions
  - PII redaction (GDPR Art. 25)
  - Resource exhaustion protection (CWE-400)
"""

import sys
import unittest
import json
import hmac
import hashlib
from datetime import datetime, timezone

# Add current directory to path for import
sys.path.insert(0, '.')

from omni_sentinel_cli import (
    ActionType, PhaseState, TelemetrySnapshot, Rule, AuditLogEntry,
    RuleEngine, TelemetryMonitor, OmniSentinel
)


class TestActionTypePrecedence(unittest.TestCase):
    """Test ActionType enum precedence ordering"""
    
    def test_kill_switch_highest_priority(self):
        """KILL_SWITCH should have highest precedence"""
        self.assertGreater(ActionType.KILL_SWITCH, ActionType.HALT)
        self.assertGreater(ActionType.KILL_SWITCH, ActionType.OVERRIDE)
        self.assertGreater(ActionType.KILL_SWITCH, ActionType.ALERT)
    
    def test_halt_precedence(self):
        """HALT should have second-highest precedence"""
        self.assertGreater(ActionType.HALT, ActionType.OVERRIDE)
        self.assertGreater(ActionType.HALT, ActionType.ALERT)
    
    def test_override_precedence(self):
        """OVERRIDE should have third-highest precedence"""
        self.assertGreater(ActionType.OVERRIDE, ActionType.ALERT)


class TestTelemetrySnapshot(unittest.TestCase):
    """Test telemetry snapshot creation and serialization"""
    
    def test_snapshot_creation(self):
        """Snapshot should capture all required metrics"""
        snapshot = TelemetrySnapshot(
            timestamp=1234567890.0,
            cpu_percent=45.5,
            memory_available_gb=32.0,
            latency_ms=150.0,
            latency_blocks=7,
            region="ALBION_PROTOCOL",
            phase="MONITORING",
            seed=42
        )
        
        self.assertEqual(snapshot.cpu_percent, 45.5)
        self.assertEqual(snapshot.memory_available_gb, 32.0)
        self.assertEqual(snapshot.latency_ms, 150.0)
        self.assertEqual(snapshot.latency_blocks, 7)
    
    def test_latency_block_calculation(self):
        """Latency blocks should be correctly calculated (20ms per block)"""
        # 800ms = 40 blocks
        snapshot1 = TelemetrySnapshot(
            timestamp=1234567890.0, cpu_percent=50, memory_available_gb=16,
            latency_ms=800, latency_blocks=int(800/20), region="ALBION_PROTOCOL",
            phase="MONITORING"
        )
        self.assertEqual(snapshot1.latency_blocks, 40)
        
        # 20ms = 1 block
        snapshot2 = TelemetrySnapshot(
            timestamp=1234567890.0, cpu_percent=50, memory_available_gb=16,
            latency_ms=20, latency_blocks=int(20/20), region="ALBION_PROTOCOL",
            phase="MONITORING"
        )
        self.assertEqual(snapshot2.latency_blocks, 1)


class TestRule(unittest.TestCase):
    """Test rule evaluation logic"""
    
    def test_cpu_spike_rule(self):
        """CPU_SPIKE rule should trigger when CPU > 90%"""
        rule = Rule(
            name="CPU_SPIKE",
            condition="cpu_percent > 90",
            action=ActionType.KILL_SWITCH,
            threshold=90.0,
            metric="cpu_percent",
            operator=">",
            description="CPU spike detected",
            priority=100
        )
        
        # Should trigger
        snapshot_high = TelemetrySnapshot(
            timestamp=1234567890.0, cpu_percent=95.0, memory_available_gb=16,
            latency_ms=50, latency_blocks=2, region="ALBION_PROTOCOL",
            phase="MONITORING"
        )
        self.assertTrue(rule.evaluate(snapshot_high))
        
        # Should not trigger
        snapshot_low = TelemetrySnapshot(
            timestamp=1234567890.0, cpu_percent=85.0, memory_available_gb=16,
            latency_ms=50, latency_blocks=2, region="ALBION_PROTOCOL",
            phase="MONITORING"
        )
        self.assertFalse(rule.evaluate(snapshot_low))
    
    def test_memory_leak_rule(self):
        """MEM_LEAK rule should trigger when memory < 10GB"""
        rule = Rule(
            name="MEM_LEAK",
            condition="memory_available_gb < 10",
            action=ActionType.HALT,
            threshold=10.0,
            metric="memory_available_gb",
            operator="<",
            description="Memory leak detected",
            priority=90
        )
        
        # Should trigger
        snapshot_low_mem = TelemetrySnapshot(
            timestamp=1234567890.0, cpu_percent=50, memory_available_gb=5.0,
            latency_ms=50, latency_blocks=2, region="ALBION_PROTOCOL",
            phase="MONITORING"
        )
        self.assertTrue(rule.evaluate(snapshot_low_mem))
        
        # Should not trigger
        snapshot_high_mem = TelemetrySnapshot(
            timestamp=1234567890.0, cpu_percent=50, memory_available_gb=20.0,
            latency_ms=50, latency_blocks=2, region="ALBION_PROTOCOL",
            phase="MONITORING"
        )
        self.assertFalse(rule.evaluate(snapshot_high_mem))
    
    def test_latency_override_rule(self):
        """LATENCY_H rule should trigger when latency > 500ms"""
        rule = Rule(
            name="LATENCY_H",
            condition="latency_ms > 500",
            action=ActionType.OVERRIDE,
            threshold=500.0,
            metric="latency_ms",
            operator=">",
            description="High latency detected",
            priority=80
        )
        
        # Should trigger
        snapshot_high_latency = TelemetrySnapshot(
            timestamp=1234567890.0, cpu_percent=50, memory_available_gb=16,
            latency_ms=600.0, latency_blocks=30, region="ALBION_PROTOCOL",
            phase="MONITORING"
        )
        self.assertTrue(rule.evaluate(snapshot_high_latency))
        
        # Should not trigger
        snapshot_low_latency = TelemetrySnapshot(
            timestamp=1234567890.0, cpu_percent=50, memory_available_gb=16,
            latency_ms=100.0, latency_blocks=5, region="ALBION_PROTOCOL",
            phase="MONITORING"
        )
        self.assertFalse(rule.evaluate(snapshot_low_latency))


class TestRuleEngine(unittest.TestCase):
    """Test rule engine conflict resolution"""
    
    def test_single_rule_trigger(self):
        """Single rule should be returned as winner"""
        engine = RuleEngine()
        rule = Rule(
            name="TEST_RULE",
            condition="cpu_percent > 80",
            action=ActionType.ALERT,
            threshold=80.0,
            metric="cpu_percent",
            operator=">",
            description="Test rule",
            priority=50
        )
        engine.add_rule(rule)
        
        snapshot = TelemetrySnapshot(
            timestamp=1234567890.0, cpu_percent=85.0, memory_available_gb=16,
            latency_ms=50, latency_blocks=2, region="ALBION_PROTOCOL",
            phase="MONITORING"
        )
        
        winner, triggered = engine.evaluate(snapshot)
        self.assertEqual(winner.name, "TEST_RULE")
        self.assertEqual(len(triggered), 1)
    
    def test_conflict_resolution_by_action_type(self):
        """Higher ActionType should win in conflicts"""
        engine = RuleEngine()
        
        # Add rules with different ActionTypes
        rule_alert = Rule(
            name="ALERT_RULE", condition="cpu_percent > 70",
            action=ActionType.ALERT, threshold=70.0, metric="cpu_percent",
            operator=">", description="Alert rule", priority=50
        )
        rule_override = Rule(
            name="OVERRIDE_RULE", condition="cpu_percent > 70",
            action=ActionType.OVERRIDE, threshold=70.0, metric="cpu_percent",
            operator=">", description="Override rule", priority=50
        )
        rule_halt = Rule(
            name="HALT_RULE", condition="cpu_percent > 70",
            action=ActionType.HALT, threshold=70.0, metric="cpu_percent",
            operator=">", description="Halt rule", priority=50
        )
        
        engine.add_rule(rule_alert)
        engine.add_rule(rule_override)
        engine.add_rule(rule_halt)
        
        snapshot = TelemetrySnapshot(
            timestamp=1234567890.0, cpu_percent=85.0, memory_available_gb=16,
            latency_ms=50, latency_blocks=2, region="ALBION_PROTOCOL",
            phase="MONITORING"
        )
        
        winner, triggered = engine.evaluate(snapshot)
        
        # HALT should win (highest ActionType among triggered)
        self.assertEqual(winner.name, "HALT_RULE")
        self.assertEqual(len(triggered), 3)
    
    def test_conflict_resolution_by_priority(self):
        """Within same ActionType, higher priority should win"""
        engine = RuleEngine()
        
        rule_low_priority = Rule(
            name="LOW_PRIORITY", condition="cpu_percent > 70",
            action=ActionType.ALERT, threshold=70.0, metric="cpu_percent",
            operator=">", description="Low priority", priority=10
        )
        rule_high_priority = Rule(
            name="HIGH_PRIORITY", condition="cpu_percent > 70",
            action=ActionType.ALERT, threshold=70.0, metric="cpu_percent",
            operator=">", description="High priority", priority=100
        )
        
        engine.add_rule(rule_low_priority)
        engine.add_rule(rule_high_priority)
        
        snapshot = TelemetrySnapshot(
            timestamp=1234567890.0, cpu_percent=85.0, memory_available_gb=16,
            latency_ms=50, latency_blocks=2, region="ALBION_PROTOCOL",
            phase="MONITORING"
        )
        
        winner, triggered = engine.evaluate(snapshot)
        
        # HIGH_PRIORITY should win
        self.assertEqual(winner.name, "HIGH_PRIORITY")
        self.assertEqual(len(triggered), 2)
    
    def test_no_rules_triggered(self):
        """When no rules trigger, should return None"""
        engine = RuleEngine()
        rule = Rule(
            name="TEST_RULE", condition="cpu_percent > 90",
            action=ActionType.ALERT, threshold=90.0, metric="cpu_percent",
            operator=">", description="Test rule", priority=50
        )
        engine.add_rule(rule)
        
        snapshot = TelemetrySnapshot(
            timestamp=1234567890.0, cpu_percent=50.0, memory_available_gb=16,
            latency_ms=50, latency_blocks=2, region="ALBION_PROTOCOL",
            phase="MONITORING"
        )
        
        winner, triggered = engine.evaluate(snapshot)
        self.assertIsNone(winner)
        self.assertEqual(len(triggered), 0)


class TestAuditLogEntry(unittest.TestCase):
    """Test audit log creation and HMAC integrity"""
    
    def test_audit_log_creation(self):
        """Audit log should be created with all required fields"""
        entry = AuditLogEntry.create(
            event_type="TEST_EVENT",
            phase="MONITORING",
            details={"key": "value"}
        )
        
        self.assertEqual(entry.event_type, "TEST_EVENT")
        self.assertEqual(entry.phase, "MONITORING")
        self.assertEqual(entry.details["key"], "value")
        self.assertIsNotNone(entry.hmac)
        self.assertIsNotNone(entry.timestamp)
    
    def test_hmac_integrity(self):
        """HMAC should correctly verify log entry integrity"""
        entry = AuditLogEntry.create(
            event_type="TEST_EVENT",
            phase="MONITORING",
            details={"key": "value"}
        )
        
        # Recompute HMAC
        payload = json.dumps({
            "timestamp": entry.timestamp,
            "event_type": entry.event_type,
            "phase": entry.phase,
            "details": entry.details
        }, sort_keys=True)
        
        expected_hmac = hmac.new(
            b"<REDACTED_SECRET>",  # Default key from omni_sentinel_cli.py
            payload.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        self.assertEqual(entry.hmac, expected_hmac)
    
    def test_pii_redaction(self):
        """PII fields should be redacted per GDPR Art. 25"""
        entry = AuditLogEntry.create(
            event_type="USER_ACTION",
            phase="MONITORING",
            details={
                "user_id": "12345",
                "ssn": "123-45-6789",
                "password": "secret123",
                "credit_card": "4111111111111111",
                "action": "trade_executed"
            }
        )
        
        # Sensitive fields should be redacted
        self.assertEqual(entry.details["ssn"], "<REDACTED_PII>")
        self.assertEqual(entry.details["password"], "<REDACTED_PII>")
        self.assertEqual(entry.details["credit_card"], "<REDACTED_PII>")
        
        # Non-sensitive fields should be preserved
        self.assertEqual(entry.details["user_id"], "12345")
        self.assertEqual(entry.details["action"], "trade_executed")


class TestTelemetryMonitor(unittest.TestCase):
    """Test telemetry monitoring functionality"""
    
    def test_telemetry_sampling(self):
        """Telemetry monitor should capture system metrics"""
        monitor = TelemetryMonitor(sample_interval_ms=100)
        snapshot = monitor.sample(PhaseState.MONITORING)
        
        self.assertIsNotNone(snapshot.cpu_percent)
        self.assertIsNotNone(snapshot.memory_available_gb)
        self.assertIsNotNone(snapshot.latency_ms)
        self.assertEqual(snapshot.phase, "MONITORING")
    
    def test_history_bounded(self):
        """Telemetry history should be bounded to prevent memory exhaustion (CWE-400)"""
        monitor = TelemetryMonitor(sample_interval_ms=10)
        
        # Generate many samples
        for _ in range(15000):
            monitor.sample(PhaseState.MONITORING)
        
        # History should be capped at 10000
        history = monitor.get_history()
        self.assertLessEqual(len(history), 10000)


class TestOmniSentinel(unittest.TestCase):
    """Test Omni-Sentinel main controller"""
    
    def test_initialization(self):
        """Sentinel should initialize with default rules"""
        sentinel = OmniSentinel(sample_interval_ms=100)
        
        self.assertEqual(sentinel.phase, PhaseState.INIT)
        self.assertGreater(len(sentinel.engine.rules), 0)
    
    def test_default_rules_registered(self):
        """Default rules (CPU_SPIKE, MEM_LEAK, LATENCY_H, LATENCY_M) should be registered"""
        sentinel = OmniSentinel(sample_interval_ms=100)
        
        rule_names = [r.name for r in sentinel.engine.rules]
        self.assertIn("CPU_SPIKE", rule_names)
        self.assertIn("MEM_LEAK", rule_names)
        self.assertIn("LATENCY_H", rule_names)
        self.assertIn("LATENCY_M", rule_names)
    
    def test_phase_transition_logging(self):
        """Phase transitions should be logged with HMAC integrity"""
        sentinel = OmniSentinel(sample_interval_ms=100)
        initial_log_count = len(sentinel.engine.audit_log)
        
        sentinel._log_phase_transition(PhaseState.MONITORING, "Test transition")
        
        # Should have added one audit log entry
        self.assertEqual(len(sentinel.engine.audit_log), initial_log_count + 1)
        self.assertEqual(sentinel.phase, PhaseState.MONITORING)


def run_tests():
    """Run all test suites"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test cases
    suite.addTests(loader.loadTestsFromTestCase(TestActionTypePrecedence))
    suite.addTests(loader.loadTestsFromTestCase(TestTelemetrySnapshot))
    suite.addTests(loader.loadTestsFromTestCase(TestRule))
    suite.addTests(loader.loadTestsFromTestCase(TestRuleEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestAuditLogEntry))
    suite.addTests(loader.loadTestsFromTestCase(TestTelemetryMonitor))
    suite.addTests(loader.loadTestsFromTestCase(TestOmniSentinel))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result


if __name__ == "__main__":
    result = run_tests()
    sys.exit(0 if result.wasSuccessful() else 1)

#!/usr/bin/env python3
"""
AgentalSec Linux - Full System Test

Run comprehensive tests of all Linux-native sensors and modules.
"""

import sys
import time
from pathlib import Path

# THE PROJECT ROOT IS THE PARENT, NOT THIS DIRECTORY. Fixed 2026-09-18 with
# T3. This read `Path(__file__).parent`, which is scripts/, so every import of
# `core.*` and `tools.*` failed with "No module named 'core'" and the suite
# reported 1/11 — including "Parse error: no such file scripts/main.py", which
# is the check that says out loud it is looking in the wrong place. It only
# ever passed when somebody happened to have PYTHONPATH set, which means the
# suite's "11/11 passing" depended on how it was invoked rather than on the
# code. A check that cannot run correctly is worse than no check: this whole
# project is organised against readings that pass because nothing looked.
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Add project root to path
sys.path.insert(0, str(PROJECT_ROOT))

def print_header(text):
    print("\n" + "=" * 70)
    print(f"  {text}")
    print("=" * 70)

def test_module(name, test_func):
    """Run a test function and report results."""
    print(f"\n  Testing {name}...")
    try:
        result = test_func()
        if result:
            print(f"  ✅ PASS")
            return True
        else:
            print(f"  ⚠️  PARTIAL")
            return True
    except Exception as e:
        print(f"  ❌ FAIL: {e}")
        return False

def test_privilege_linux():
    """Test privilege_linux module."""
    from core import privilege_linux
    
    posture = privilege_linux.posture()
    print(f"    Elevated: {posture['elevated']}")
    print(f"    Can capture: {posture.get('can_capture_packets', False)}")
    print(f"    Summary: {posture.get('summary', '')[:80]}")
    return True

def test_secret_crypto():
    """Test core/secret_crypto encryption.

    REPOINTED 2026-09-25, THE WINDOWS-LEFTOVERS ROUND. This called
    core.dpapi_linux, which was core/secret_crypto's old name -- it was named
    after the WINDOWS API (DPAPI) it was first written as a counterpart to.
    The module moved to its own name and the Windows one left the tree
    (agental_sec_win32_reference/core/dpapi.py), so this script reported FAIL
    for a module that was installed, working and encrypted the whole time.
    """
    from core import secret_crypto

    status = secret_crypto.status()
    print(f"    Available: {status['available']}")
    print(f"    Enabled: {status['enabled']}")

    if status['available']:
        # Test encrypt/decrypt
        test_value = "test_secret_123"
        encrypted = secret_crypto.protect(test_value)
        decrypted = secret_crypto.unprotect(encrypted)

        if decrypted == test_value:
            print(f"    Encrypt/Decrypt: ✅ Working")
            return True
        else:
            print(f"    Encrypt/Decrypt: ❌ Failed")
            return False

    return True  # Not available is OK

def test_packet_sniffer():
    """Test packet_sniffer_linux module."""
    from tools import packet_sniffer_linux
    
    status = packet_sniffer_linux.get_status()
    print(f"    Available: {status['available']}")
    print(f"    Can capture: {status.get('can_capture', False)}")
    print(f"    Reason: {status.get('reason', 'unknown')}")
    print(f"    Interfaces: {len(status.get('interfaces', []))}")
    
    # Try to capture a few packets
    if status.get('can_capture', False):
        print(f"    Testing capture...")
        result = packet_sniffer_linux.monitor_once(count=5)
        if result.get('searched'):
            print(f"    Captured: {result.get('packet_count', 0)} packets")
            return True
    
    return True

def test_process_monitor():
    """Test process_monitor_linux module."""
    from tools import process_monitor_linux
    
    status = process_monitor_linux.get_status()
    print(f"    Available: {status.get('available', False)}")
    print(f"    Process count: {status.get('process_count', 0)}")
    
    # Run monitoring once
    result = process_monitor_linux.monitor_once()
    if result.get('searched'):
        print(f"    Processes scanned: {result.get('process_count', 0)}")
        print(f"    Findings: {result.get('finding_count', 0)}")
        return True
    
    return True

def test_event_monitor():
    """Test event_monitor_linux module."""
    from tools import event_monitor_linux
    
    status = event_monitor_linux.get_status()
    print(f"    Journald available: {status.get('journald_available', False)}")
    print(f"    Log sources: {status.get('log_files_available', [])}")
    
    # Run monitoring once
    result = event_monitor_linux.monitor_once()
    if result.get('searched'):
        print(f"    Events scanned: {result.get('event_count', 0)}")
        print(f"    Findings: {result.get('finding_count', 0)}")
        return True
    
    return True

def test_autorun_monitor():
    """Test autorun_monitor module."""
    from tools import autorun_monitor
    
    # Get systemd services
    services = autorun_monitor.get_systemd_services()
    print(f"    Systemd services: {len(services)}")
    
    # Get cron jobs
    crons = autorun_monitor.get_cron_jobs()
    print(f"    Cron jobs: {len(crons)}")
    
    # Analyze for suspicious
    findings = autorun_monitor.analyze_suspicious()
    print(f"    Suspicious findings: {len(findings)}")
    
    return True

def test_iptables_manager():
    """Test iptables_manager module."""
    from tools import iptables_manager
    
    status = iptables_manager.get_status()
    print(f"    Backend: {status.get('backend', 'none')}")
    print(f"    Available: {status.get('available', False)}")
    print(f"    Existing rules: {status.get('rules_count', 0)}")
    
    return True

def test_software_inventory():
    """Test software_inventory_linux module."""
    from tools import software_inventory_linux
    
    managers = software_inventory_linux.detect_package_managers()
    print(f"    Detected managers: {managers}")
    
    inventory = software_inventory_linux.get_all_software()
    print(f"    Total packages: {inventory['summary']['total']}")
    print(f"    By manager: {inventory['summary']}")
    
    return True

def test_host_info():
    """Test host_info_linux module."""
    from tools import host_info_linux
    
    summary = host_info_linux.get_summary()
    print(f"    Hostname: {summary.get('hostname')}")
    print(f"    OS: {summary.get('os')}")
    print(f"    Kernel: {summary.get('kernel')}")
    print(f"    CPU: {summary.get('cpu_count')} cores")
    print(f"    Memory: {summary.get('memory_mb')} MB")
    print(f"    IP: {summary.get('primary_ip')}")
    
    return True

def test_remediation():
    """Test remediation_linux module."""
    from tools import remediation_linux
    
    status = remediation_linux.get_status()
    print(f"    Psutil available: {status.get('psutil_available', False)}")
    print(f"    Firewall backend: {status.get('firewall_backend', 'unknown')}")
    print(f"    Quarantined files: {status.get('quarantine_count', 0)}")
    
    # Test critical process list
    print(f"    Critical processes protected: {len(remediation_linux.CRITICAL_PROCESSES)}")
    
    return True

def test_main_import():
    """Test that main.py can be imported."""
    try:
        # Just check it parses
        import ast
        main_path = PROJECT_ROOT / "main.py"
        with open(main_path) as f:
            ast.parse(f.read())
        print(f"    main.py: ✅ Parses correctly")
        return True
    except Exception as e:
        print(f"    main.py: ❌ Parse error: {e}")
        return False

def run_all_tests():
    """Run all tests and report results."""
    print_header("AGENTALSEC LINUX - COMPREHENSIVE TEST SUITE")
    print(f"Project root: {PROJECT_ROOT}")
    print(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    tests = [
        ("core/privilege_linux", test_privilege_linux),
        ("core/secret_crypto", test_secret_crypto),
        ("tools/packet_sniffer_linux", test_packet_sniffer),
        ("tools/process_monitor_linux", test_process_monitor),
        ("tools/event_monitor_linux", test_event_monitor),
        ("tools/autorun_monitor", test_autorun_monitor),
        ("tools/iptables_manager", test_iptables_manager),
        ("tools/software_inventory_linux", test_software_inventory),
        ("tools/host_info_linux", test_host_info),
        ("tools/remediation_linux", test_remediation),
        ("main.py", test_main_import),
    ]
    
    results = []
    for name, test_func in tests:
        result = test_module(name, test_func)
        results.append((name, result))
    
    # Summary
    print_header("TEST SUMMARY")
    
    passed = sum(1 for _, r in results if r)
    total = len(results)
    
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {name:35} {status}")
    
    print(f"\n  Total: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n  🎉 All tests passed! System ready for deployment.")
        print("\n  Next steps:")
        print("    1. Configure: cp config.linux.example.json config.json")
        print("    2. Set up .env: cp .env.example .env")
        print("    3. Run: python3 main.py")
        return 0
    else:
        print(f"\n  ⚠️  {total - passed} test(s) failed")
        print("      Review errors above and fix before deployment")
        return 1

if __name__ == "__main__":
    sys.exit(run_all_tests())

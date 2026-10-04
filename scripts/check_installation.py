#!/usr/bin/env python3
"""
AgentalSec Linux - Quick Start Verification

Run this script to verify your installation is ready.
"""

import sys
import subprocess
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent

def print_header(text):
    print("\n" + "=" * 60)
    print(f"  {text}")
    print("=" * 60)

def check_python_version():
    """Verify Python 3.11+"""
    version = sys.version_info
    print(f"Python version: {version.major}.{version.minor}.{version.micro}")
    if version.major < 3 or (version.major == 3 and version.minor < 11):
        print("  ❌ FAIL: Python 3.11+ required")
        return False
    print("  ✅ PASS")
    return True

def check_dependencies():
    """Check required Python packages"""
    print_header("CHECKING DEPENDENCIES")
    
    required = {
        "flask": "Flask web framework",
        "psutil": "Process and system monitoring",
        "scapy": "Packet capture and analysis",
        "paramiko": "SSH for remote monitoring",
        "cryptography": "Encryption for secrets",
    }
    
    missing = []
    for package, description in required.items():
        try:
            __import__(package)
            print(f"  ✅ {package:15} - {description}")
        except ImportError:
            print(f"  ❌ {package:15} - {description}")
            missing.append(package)
    
    if missing:
        print(f"\n  Install missing: pip install --user --break-system-packages {' '.join(missing)}")
        return False
    
    print("  ✅ All dependencies available")
    return True

def check_system_tools():
    """Check required system tools"""
    print_header("CHECKING SYSTEM TOOLS")
    
    tools = {
        "iptables": "Firewall management",
        "journalctl": "System log access",
        "ss": "Network socket inspection",
    }
    
    missing = []
    for tool, purpose in tools.items():
        result = subprocess.run(
            ["which", tool],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            print(f"  ✅ {tool:15} - {purpose}")
        else:
            print(f"  ⚠️  {tool:15} - {purpose} (optional)")
            # Don't fail on optional tools
    
    return True

def check_packet_capture():
    """Check if packet capture is possible"""
    print_header("CHECKING PACKET CAPTURE CAPABILITY")
    
    # Check if root
    import os
    if os.geteuid() == 0:
        print("  ✅ Running as root - full capture available")
        return True
    
    # Check CAP_NET_RAW
    import socket
    try:
        test_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
        test_sock.close()
        print("  ✅ Has CAP_NET_RAW capability")
        return True
    except (PermissionError, OSError):
        pass
    
    # Check group membership
    try:
        import grp
        user = os.environ.get("USER", "")
        for group_name in ["wireshark", "pcap", "netdev"]:
            try:
                group = grp.getgrnam(group_name)
                if user in group.gr_mem:
                    print(f"  ✅ Member of {group_name} group")
                    return True
            except KeyError:
                pass
    except Exception:
        pass
    
    print("  ⚠️  No raw socket access")
    print("      Options:")
    print("        1. Run with: sudo python3 main.py")
    print("        2. Grant capability: sudo setcap cap_net_raw+ep /usr/bin/python3")
    print("        3. Add to group: sudo usermod -aG wireshark $USER")
    return False

def check_config_files():
    """Check configuration files exist"""
    print_header("CHECKING CONFIGURATION")
    
    config_file = PROJECT_ROOT / "config.json"
    env_file = PROJECT_ROOT / ".env"
    
    if config_file.exists():
        print(f"  ✅ config.json found")
    else:
        print(f"  ⚠️  config.json missing - copy from config.linux.example.json")
    
    if env_file.exists():
        print(f"  ✅ .env found")
    else:
        print(f"  ⚠️  .env missing - copy from .env.example")
    
    return True

def check_database():
    """Check database readiness"""
    print_header("CHECKING DATABASE")
    
    db_file = PROJECT_ROOT / "agental_sec_linux.db"
    schema_file = PROJECT_ROOT / "Schema.SQL"
    
    if schema_file.exists():
        print(f"  ✅ Schema.SQL found")
    else:
        print(f"  ❌ Schema.SQL missing")
        return False
    
    if db_file.exists():
        print(f"  ✅ Database exists")
    else:
        print(f"  ℹ️  Database will be created on first run")
    
    return True

def check_directory_structure():
    """Verify directory structure"""
    print_header("CHECKING DIRECTORY STRUCTURE")
    
    required_dirs = ["core", "tools", "api", "scripts", "logs", "data"]
    
    for dir_name in required_dirs:
        dir_path = PROJECT_ROOT / dir_name
        if dir_path.exists() and dir_path.is_dir():
            print(f"  ✅ {dir_name}/")
        else:
            print(f"  ❌ {dir_name}/ missing")
            return False
    
    return True

def main():
    print_header("AGENTALSEC LINUX - INSTALLATION CHECK")
    print(f"Project root: {PROJECT_ROOT}")
    
    checks = [
        ("Python Version", check_python_version()),
        ("Dependencies", check_dependencies()),
        ("System Tools", check_system_tools()),
        ("Packet Capture", check_packet_capture()),
        ("Configuration", check_config_files()),
        ("Database", check_database()),
        ("Directory Structure", check_directory_structure()),
    ]
    
    print_header("SUMMARY")
    
    passed = sum(1 for _, result in checks if result)
    total = len(checks)
    
    for name, result in checks:
        status = "✅ PASS" if result else "⚠️  NEEDS ATTENTION"
        print(f"  {name:25} {status}")
    
    print(f"\n  Total: {passed}/{total} checks passed")
    
    if passed == total:
        print("\n  🎉 Installation ready! Run: python3 main.py")
        return 0
    else:
        print("\n  ⚠️  Some checks need attention before first run")
        print("      See SETUP.md for the setup steps")
        return 1

if __name__ == "__main__":
    sys.exit(main())

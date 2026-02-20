"""
============================================================
MCP-SPLUNK PROJECT — MASTER SETUP VERIFICATION SCRIPT
============================================================
Author: Sayyed Abuzar (Team Lead)
Project: MCP Server for Splunk — Phase 1
Date: Week 1, Day 1
Purpose: Verify all tools and libraries are correctly installed
============================================================
"""

import sys
import os
import subprocess
import shutil
from datetime import datetime

# Colors for terminal output (Windows compatible)
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def check_mark(status):
    """Return checkmark or cross based on status"""
    if status:
        return f"{Colors.GREEN}✅ PASS{Colors.END}"
    else:
        return f"{Colors.RED}❌ FAIL{Colors.END}"

def get_command_output(command):
    """Run a command and return its output"""
    try:
        result = subprocess.run(
            command, 
            capture_output=True, 
            text=True, 
            shell=True,
            timeout=10
        )
        return result.stdout.strip() if result.stdout.strip() else result.stderr.strip()
    except Exception as e:
        return f"Error: {e}"

print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
print(f"{Colors.BOLD}  MCP-SPLUNK PROJECT — SETUP VERIFICATION REPORT{Colors.END}")
print(f"{Colors.BOLD}{'='*60}{Colors.END}")
print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"  Machine: {os.environ.get('COMPUTERNAME', 'Unknown')}")
print(f"  User: {os.environ.get('USERNAME', 'Unknown')}")
print(f"{'='*60}\n")

# Track results
results = []
total_checks = 0
passed_checks = 0

# ============================================================
# CHECK 1: Python Version
# ============================================================
print(f"{Colors.BLUE}[1/8] PYTHON{Colors.END}")
python_version = sys.version
is_python_ok = sys.version_info >= (3, 12)
print(f"  Version: {python_version}")
print(f"  Path: {sys.executable}")
print(f"  Status: {check_mark(is_python_ok)}")
if not is_python_ok:
    print(f"  {Colors.YELLOW}⚠ Need Python 3.12+{Colors.END}")
total_checks += 1
if is_python_ok: passed_checks += 1
print()

# ============================================================
# CHECK 2: pip
# ============================================================
print(f"{Colors.BLUE}[2/8] PIP{Colors.END}")
pip_output = get_command_output("pip --version")
is_pip_ok = "pip" in pip_output.lower() and "error" not in pip_output.lower()
print(f"  Output: {pip_output}")
print(f"  Status: {check_mark(is_pip_ok)}")
total_checks += 1
if is_pip_ok: passed_checks += 1
print()

# ============================================================
# CHECK 3: Required Python Libraries
# ============================================================
print(f"{Colors.BLUE}[3/8] PYTHON LIBRARIES{Colors.END}")

libraries = {
    'splunklib': 'splunk-sdk',
    'mcp': 'mcp', 
    'requests': 'requests'
}

all_libs_ok = True
for import_name, package_name in libraries.items():
    try:
        module = __import__(import_name)
        version = getattr(module, '__version__', 'version not available')
        print(f"  {package_name}: {check_mark(True)} (version: {version})")
    except ImportError:
        print(f"  {package_name}: {check_mark(False)}")
        all_libs_ok = False

total_checks += 1
if all_libs_ok: passed_checks += 1
print()

# ============================================================
# CHECK 4: VS Code
# ============================================================
print(f"{Colors.BLUE}[4/8] VS CODE{Colors.END}")
vscode_output = get_command_output("code --version")
is_vscode_ok = len(vscode_output) > 0 and "error" not in vscode_output.lower()
if is_vscode_ok:
    vscode_version = vscode_output.split('\n')[0]
    print(f"  Version: {vscode_version}")
else:
    print(f"  Output: {vscode_output}")
print(f"  Status: {check_mark(is_vscode_ok)}")
total_checks += 1
if is_vscode_ok: passed_checks += 1
print()

# ============================================================
# CHECK 5: Git
# ============================================================
print(f"{Colors.BLUE}[5/8] GIT{Colors.END}")
git_output = get_command_output("git --version")
is_git_ok = "git version" in git_output.lower()
print(f"  Output: {git_output}")

# Check git config
git_name = get_command_output("git config --global user.name")
git_email = get_command_output("git config --global user.email")
print(f"  User: {git_name}")
print(f"  Email: {git_email}")
print(f"  Status: {check_mark(is_git_ok)}")
total_checks += 1
if is_git_ok: passed_checks += 1
print()

# ============================================================
# CHECK 6: Git Repository
# ============================================================
print(f"{Colors.BLUE}[6/8] GIT REPOSITORY{Colors.END}")
is_git_repo = os.path.exists('.git')
gitignore_exists = os.path.exists('.gitignore')
requirements_exists = os.path.exists('requirements.txt')
print(f"  Git repo initialized: {check_mark(is_git_repo)}")
print(f"  .gitignore exists: {check_mark(gitignore_exists)}")
print(f"  requirements.txt exists: {check_mark(requirements_exists)}")

git_log = get_command_output("git log --oneline")
if git_log and "error" not in git_log.lower():
    print(f"  Latest commit: {git_log.split(chr(10))[0]}")

is_repo_ok = is_git_repo and gitignore_exists and requirements_exists
total_checks += 1
if is_repo_ok: passed_checks += 1
print()

# ============================================================
# CHECK 7: Splunk
# ============================================================
print(f"{Colors.BLUE}[7/8] SPLUNK{Colors.END}")
splunk_output = get_command_output("splunk version")
is_splunk_ok = "splunk" in splunk_output.lower() and "not recognized" not in splunk_output.lower()
print(f"  Output: {splunk_output}")

# Check if Splunk web is reachable
try:
    import requests
    response = requests.get("http://localhost:8000", timeout=5, verify=False)
    splunk_web = response.status_code == 200
    print(f"  Web UI (localhost:8000): {check_mark(splunk_web)}")
except:
    splunk_web = False
    print(f"  Web UI (localhost:8000): {check_mark(False)}")
    print(f"  {Colors.YELLOW}⚠ Make sure Splunk is running{Colors.END}")

# Check REST API
try:
    response = requests.get("https://localhost:8089", timeout=5, verify=False)
    splunk_api = True
    print(f"  REST API (localhost:8089): {check_mark(True)}")
except:
    splunk_api = False
    print(f"  REST API (localhost:8089): {check_mark(False)}")

print(f"  Status: {check_mark(is_splunk_ok)}")
total_checks += 1
if is_splunk_ok: passed_checks += 1
print()

# ============================================================
# CHECK 8: Node.js (for future MCP tools)
# ============================================================
print(f"{Colors.BLUE}[8/8] NODE.JS{Colors.END}")
node_output = get_command_output("node --version")
npm_output = get_command_output("npm --version")
is_node_ok = node_output.startswith("v")
print(f"  Node: {node_output}")
print(f"  npm: {npm_output}")
print(f"  Status: {check_mark(is_node_ok)}")
total_checks += 1
if is_node_ok: passed_checks += 1
print()

# ============================================================
# FINAL REPORT
# ============================================================
print(f"{'='*60}")
print(f"{Colors.BOLD}  FINAL RESULTS: {passed_checks}/{total_checks} checks passed{Colors.END}")
print(f"{'='*60}")

if passed_checks == total_checks:
    print(f"""
{Colors.GREEN}{Colors.BOLD}
  ╔══════════════════════════════════════════════════════╗
  ║                                                      ║
  ║   🎉 ALL CHECKS PASSED! SETUP IS PERFECT! 🎉       ║
  ║                                                      ║
  ║   You are READY to start building the MCP Server!   ║
  ║   Week 1, Day 1 is COMPLETE!                        ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝
{Colors.END}""")
elif passed_checks >= total_checks - 1:
    print(f"""
{Colors.YELLOW}
  ╔══════════════════════════════════════════════════════╗
  ║                                                      ║
  ║   ⚠️  ALMOST THERE! Minor issues to fix.            ║
  ║   Check the FAIL items above and fix them.          ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝
{Colors.END}""")
else:
    print(f"""
{Colors.RED}
  ╔══════════════════════════════════════════════════════╗
  ║                                                      ║
  ║   ❌ MULTIPLE ISSUES FOUND                           ║
  ║   Check each FAIL item above and fix them.          ║
  ║   Ask your mentor for help!                         ║
  ║                                                      ║
  ╚══════════════════════════════════════════════════════╝
{Colors.END}""")

print(f"\n{'='*60}")
print(f"  Report generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print(f"{'='*60}\n")
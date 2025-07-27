#!/bin/bash

# Mobile-PT Repository Command Validation Script
# This script validates that the commands and tools mentioned in the documentation are available

echo "🔍 Mobile-PT Repository Command Validation"
echo "=========================================="

# Color codes for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
TOTAL_CHECKS=0
PASSED_CHECKS=0
FAILED_CHECKS=0

# Function to check if a command exists
check_command() {
    local cmd=$1
    local description=$2
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if command -v "$cmd" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $description ($cmd)"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        echo -e "${RED}✗${NC} $description ($cmd) - Not found"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Function to check if a Python package is installed
check_python_package() {
    local package=$1
    local description=$2
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if python3 -c "import $package" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $description (Python package: $package)"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        echo -e "${RED}✗${NC} $description (Python package: $package) - Not installed"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

# Function to test a simple command
test_command() {
    local cmd=$1
    local description=$2
    TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    
    if eval "$cmd" &> /dev/null; then
        echo -e "${GREEN}✓${NC} $description"
        PASSED_CHECKS=$((PASSED_CHECKS + 1))
    else
        echo -e "${RED}✗${NC} $description - Failed"
        FAILED_CHECKS=$((FAILED_CHECKS + 1))
    fi
}

echo -e "\n📱 Basic System Tools"
echo "===================="
check_command "git" "Git version control"
check_command "curl" "HTTP client"
check_command "wget" "File downloader"
check_command "unzip" "Archive extractor"
check_command "python3" "Python 3 interpreter"
check_command "pip3" "Python package manager"
check_command "node" "Node.js runtime"
check_command "jq" "JSON processor"

echo -e "\n🔧 Development Tools"
echo "==================="
check_command "sqlite3" "SQLite database"
check_command "objdump" "Object file analyzer"
check_command "strings" "String extractor"
check_command "nm" "Symbol table viewer"
check_command "file" "File type detector"
check_command "hexdump" "Hex viewer"

echo -e "\n🤖 Android Tools"
echo "================"
check_command "adb" "Android Debug Bridge"
check_command "aapt" "Android Asset Packaging Tool"
check_command "apktool" "APK reverse engineering tool"
check_command "jadx" "Dex to Java decompiler"

echo -e "\n🍎 iOS Tools (macOS only)"
echo "========================"
check_command "xcode-select" "Xcode command line tools"
check_command "class-dump" "Objective-C class dumper"
check_command "otool" "Mach-O file analyzer"
check_command "codesign" "Code signing tool"
check_command "plutil" "Property list utility"

echo -e "\n📱 Flutter Tools"
echo "================"
check_command "flutter" "Flutter SDK"
check_command "dart" "Dart language"

echo -e "\n🔍 Security Tools"
echo "================="
check_command "frida" "Dynamic instrumentation"
check_command "frida-ps" "FRIDA process scanner"
check_command "mitmproxy" "HTTP proxy"
check_command "nmap" "Network scanner"
check_command "sslscan" "SSL/TLS scanner"

echo -e "\n🐍 Python Security Packages"
echo "==========================="
check_python_package "requests" "HTTP library"
check_python_package "urllib3" "HTTP client"

echo -e "\n📝 JavaScript Syntax Validation"
echo "==============================="
if [ -d "frida-scripts" ]; then
    for script in $(find frida-scripts -name "*.js" 2>/dev/null); do
        if node -c "$script" 2>/dev/null; then
            echo -e "${GREEN}✓${NC} $script - Syntax OK"
            PASSED_CHECKS=$((PASSED_CHECKS + 1))
        else
            echo -e "${RED}✗${NC} $script - Syntax Error"
            FAILED_CHECKS=$((FAILED_CHECKS + 1))
        fi
        TOTAL_CHECKS=$((TOTAL_CHECKS + 1))
    done
else
    echo -e "${YELLOW}⚠${NC} frida-scripts directory not found"
fi

echo -e "\n🧪 Command Testing"
echo "=================="
test_command "echo '{\"test\": \"value\"}' | jq '.'" "JSON processing test"
test_command "python3 -c 'print(\"Hello World\")'" "Python execution test"
test_command "sqlite3 --version" "SQLite version check"

echo -e "\n📊 Summary"
echo "========="
echo "Total checks: $TOTAL_CHECKS"
echo -e "Passed: ${GREEN}$PASSED_CHECKS${NC}"
echo -e "Failed: ${RED}$FAILED_CHECKS${NC}"

if [ $FAILED_CHECKS -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All validation checks passed!${NC}"
    exit 0
else
    echo -e "\n${YELLOW}⚠ Some checks failed. Review the missing tools above.${NC}"
    echo "Note: Some tools are platform-specific (e.g., iOS tools only work on macOS)"
    exit 1
fi
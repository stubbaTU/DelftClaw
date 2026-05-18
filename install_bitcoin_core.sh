#!/bin/bash
# Install Bitcoin Core for Linux/WSL
# Usage: bash install_bitcoin_core.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Bitcoin Core Installation Script${NC}"
echo "=================================="

# Detect OS
if [[ "$OSTYPE" == "linux-gnu"* ]] || [[ -f /proc/version && grep -i microsoft /proc/version ]]; then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo -e "${RED}Unsupported OS: $OSTYPE${NC}"
    exit 1
fi

echo -e "${GREEN}Detected OS: $OS${NC}"

# Download and install Bitcoin Core
case $OS in
    linux)
        echo "Downloading Bitcoin Core 26.0 (x86_64-linux)..."

        # Create temp directory
        TMPDIR=$(mktemp -d)
        cd "$TMPDIR"

        # Download
        if command -v curl &> /dev/null; then
            curl -fsSL https://bitcoin.org/bin/bitcoin-core-26.0/bitcoin-26.0-x86_64-linux-gnu.tar.gz -o bitcoin.tar.gz
        elif command -v wget &> /dev/null; then
            wget -q https://bitcoin.org/bin/bitcoin-core-26.0/bitcoin-26.0-x86_64-linux-gnu.tar.gz -O bitcoin.tar.gz
        else
            echo -e "${RED}Neither curl nor wget found. Please install one of them.${NC}"
            exit 1
        fi

        # Extract
        tar -xzf bitcoin.tar.gz

        # Install
        echo "Installing Bitcoin Core to /usr/local/bin..."
        sudo install -m 0755 -o root -g root -t /usr/local/bin bitcoin-26.0/bin/*

        # Cleanup
        cd -
        rm -rf "$TMPDIR"

        echo -e "${GREEN}✓ Bitcoin Core installed successfully${NC}"
        ;;

    macos)
        echo "Downloading Bitcoin Core 26.0 (macOS)..."

        # Create temp directory
        TMPDIR=$(mktemp -d)
        cd "$TMPDIR"

        # Try to detect architecture
        if [[ $(uname -m) == 'arm64' ]]; then
            ARCH="arm64"
        else
            ARCH="x86_64"
        fi

        # Download
        curl -fsSL "https://bitcoin.org/bin/bitcoin-core-26.0/bitcoin-26.0-${ARCH}-apple-darwin.tar.gz" -o bitcoin.tar.gz

        # Extract
        tar -xzf bitcoin.tar.gz

        # Install to /usr/local/bin
        echo "Installing Bitcoin Core to /usr/local/bin..."
        sudo install -m 0755 -o root -g wheel -t /usr/local/bin bitcoin-26.0/bin/*

        # Cleanup
        cd -
        rm -rf "$TMPDIR"

        echo -e "${GREEN}✓ Bitcoin Core installed successfully${NC}"
        ;;
esac

# Verify installation
echo ""
echo "Verifying installation..."
if command -v bitcoind &> /dev/null && command -v bitcoin-cli &> /dev/null; then
    echo -e "${GREEN}✓ bitcoind and bitcoin-cli are available${NC}"
    bitcoind --version
    bitcoind -regtest -daemon
    sleep 2
    if bitcoin-cli -regtest ping 2>/dev/null | grep -q pong; then
        echo -e "${GREEN}✓ Bitcoin regtest daemon is running${NC}"
        echo ""
        echo "Next steps:"
        echo "  1. Run: python deploy/init_regtest_wallets.py --initial-balance 500000"
        echo "  2. Run: python -m agent.example_regtest_setup --agent alice --use-regtest"
    else
        echo -e "${YELLOW}⚠ Bitcoin daemon started but regtest check failed${NC}"
        echo "Try manually: bitcoind -regtest -daemon"
    fi
else
    echo -e "${YELLOW}⚠ Bitcoin installation may have failed. Check manually:${NC}"
    echo "  which bitcoind"
    echo "  which bitcoin-cli"
fi


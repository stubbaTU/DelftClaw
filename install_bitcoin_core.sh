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
if [[ "$OSTYPE" == "linux-gnu"* ]] || ([[ -f /proc/version ]] && grep -q -i microsoft /proc/version); then
    OS="linux"
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS="macos"
else
    echo -e "${RED}Unsupported OS: $OSTYPE${NC}"
    exit 1
fi

echo -e "${GREEN}Detected OS: $OS${NC}"

# Allow overriding version via env or first arg
VERSION="${1:-${BITCOIN_VERSION:-26.0}}"

# helper: attempt package manager install fallback
attempt_package_install() {
    echo "Attempting package-manager installation fallback..."

    # Ubuntu/Debian: prefer official snap package when available
    if command -v snap &> /dev/null; then
        echo "Detected snap. Trying official bitcoin-core snap..."
        if sudo snap install bitcoin-core; then
            echo -e "${GREEN}✓ Bitcoin Core installed via snap${NC}"
            return 0
        fi
        echo -e "${YELLOW}Snap install failed; continuing to other fallbacks.${NC}"
    fi

    # macOS Homebrew
    if [[ "$OS" == "macos" ]] && command -v brew &> /dev/null; then
        echo "Detected Homebrew. Installing bitcoin-core via brew..."
        if brew install bitcoin-core; then
            echo -e "${GREEN}✓ Bitcoin Core installed via brew${NC}"
            return 0
        fi
        echo -e "${YELLOW}brew install failed. Please install manually:${NC}"
        echo "See: https://bitcoincore.org/en/download/"
        return 1
    fi

    echo -e "${YELLOW}No suitable package-manager fallback found. Please install Bitcoin Core manually:${NC}"
    echo "  https://bitcoincore.org/en/download/"
    return 1
}

# Download and install Bitcoin Core
case $OS in
    linux)
        echo "Downloading Bitcoin Core ${VERSION} (x86_64-linux)..."

        # Create temp directory
        TMPDIR=$(mktemp -d)
        cd "$TMPDIR"

        # Build download URL (allow overriding arch if needed later)
        DOWNLOAD_BASE="https://bitcoincore.org/bin/bitcoin-core-${VERSION}"
        DOWNLOAD_URL="${DOWNLOAD_BASE}/bitcoin-${VERSION}-x86_64-linux-gnu.tar.gz"

        # Download (gracefully handle 404 / failure and fall back to package manager)
        DL_OK=0
        if command -v curl &> /dev/null; then
            if curl -fSL "$DOWNLOAD_URL" -o bitcoin.tar.gz; then
                DL_OK=1
            else
                echo -e "${YELLOW}Download from $DOWNLOAD_URL failed.${NC}"
            fi
        elif command -v wget &> /dev/null; then
            if wget -q "$DOWNLOAD_URL" -O bitcoin.tar.gz; then
                DL_OK=1
            else
                echo -e "${YELLOW}Download from $DOWNLOAD_URL failed.${NC}"
            fi
        else
            echo -e "${RED}Neither curl nor wget found. Will try package-manager fallback.${NC}"
        fi

        if [ "$DL_OK" -ne 1 ]; then
            cd - >/dev/null 2>&1 || true
            rm -rf "$TMPDIR"
            if attempt_package_install; then
                exit 0
            else
                echo -e "${RED}Automatic installation failed. Exiting.${NC}"
                exit 1
            fi
        fi

        # Extract
        tar -xzf bitcoin.tar.gz

        # Install
        echo "Installing Bitcoin Core to /usr/local/bin..."
        sudo install -m 0755 -o root -g root -t /usr/local/bin bitcoin-${VERSION}/bin/*

        # Cleanup
        cd -
        rm -rf "$TMPDIR"

        echo -e "${GREEN}✓ Bitcoin Core installed successfully${NC}"
        ;;

    macos)
        echo "Downloading Bitcoin Core ${VERSION} (macOS)..."

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
        DOWNLOAD_URL="https://bitcoincore.org/bin/bitcoin-core-${VERSION}/bitcoin-${VERSION}-${ARCH}-apple-darwin.tar.gz"
        if ! curl -fSL "$DOWNLOAD_URL" -o bitcoin.tar.gz; then
            echo -e "${YELLOW}Download from $DOWNLOAD_URL failed.${NC}"
            cd - >/dev/null 2>&1 || true
            rm -rf "$TMPDIR"
            if attempt_package_install; then
                exit 0
            else
                echo -e "${RED}Automatic installation failed. Exiting.${NC}"
                exit 1
            fi
        fi

        # Extract
        tar -xzf bitcoin.tar.gz

        # Install to /usr/local/bin
        echo "Installing Bitcoin Core to /usr/local/bin..."
        sudo install -m 0755 -o root -g wheel -t /usr/local/bin bitcoin-${VERSION}/bin/*

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


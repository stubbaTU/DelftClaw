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
    # Debian/Ubuntu (attempt PPA)
    if command -v apt-get &> /dev/null; then
        echo "Detected apt-get. Trying Ubuntu PPA (bitcoin/bitcoin)..."
        sudo apt-get update -y || true
        if ! command -v add-apt-repository &> /dev/null; then
            echo "Installing software-properties-common to add PPA..."
            sudo apt-get install -y software-properties-common || true
        fi
        if command -v add-apt-repository &> /dev/null; then
            sudo add-apt-repository -y ppa:bitcoin/bitcoin || true
            sudo apt-get update -y || true
            sudo apt-get install -y bitcoind bitcoin-cli || {
                echo -e "${YELLOW}Could not install via apt. Please install manually:${NC}"
                echo "See: https://bitcoin.org/en/download"
                return 1
            }
            echo -e "${GREEN}✓ Bitcoin Core installed via apt${NC}"
            return 0
        fi
    fi

    # macOS Homebrew
    if [[ "$OS" == "macos" ]] && command -v brew &> /dev/null; then
        echo "Detected Homebrew. Installing bitcoin-core via brew..."
        brew install bitcoin-core || {
            echo -e "${YELLOW}brew install failed. Please install manually:${NC}"
            echo "See: https://bitcoin.org/en/download"
            return 1
        }
        echo -e "${GREEN}✓ Bitcoin Core installed via brew${NC}"
        return 0
    fi

    echo -e "${YELLOW}No suitable package-manager fallback found. Please install Bitcoin Core manually:${NC}"
    echo "  https://bitcoin.org/en/download"
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
        DOWNLOAD_URL="https://bitcoin.org/bin/bitcoin-core-${VERSION}/bitcoin-${VERSION}-x86_64-linux-gnu.tar.gz"

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
            # cleanup temp dir before fallback attempt
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


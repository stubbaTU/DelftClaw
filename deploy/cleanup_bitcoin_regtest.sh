#!/usr/bin/env bash
###############################################################################
# cleanup_bitcoin_regtest.sh
#
# Stop a Bitcoin Core regtest node and remove all local blockchain / wallet
# state for a clean restart on a VPS.
#
# Usage:
#   ./deploy/cleanup_bitcoin_regtest.sh [OPTIONS]
#
# Options:
#   --bitcoin-data /path/to/dir    Bitcoin data directory (default: ~/.bitcoin)
#   --bitcoin-cli /path/to/cli     Path to bitcoin-cli binary (default: bitcoin-cli)
#   --remove-config                Also delete bitcoin.conf
#   --yes                          Skip confirmation prompt
#   --help                         Show this help
#
# This script will:
#   1. Stop bitcoind cleanly when possible
#   2. Remove regtest chain data (blocks, chainstate, wallets, peers, etc.)
#   3. Optionally remove bitcoin.conf
#   4. Leave other network data untouched unless it is inside the regtest tree
###############################################################################

set -euo pipefail

BITCOIN_DATA="${HOME}/.bitcoin"
BITCOIN_CLI="${BITCOIN_CLI:-bitcoin-cli}"
REMOVE_CONFIG=0
ASSUME_YES=0
RPC_USER="admin"
RPC_PASSWORD="admin"

usage() {
    cat <<'EOF'
cleanup_bitcoin_regtest.sh

Stop Bitcoin Core regtest and remove all local blockchain / wallet state.

Usage:
  ./deploy/cleanup_bitcoin_regtest.sh [OPTIONS]

Options:
  --bitcoin-data /path/to/dir    Bitcoin data directory (default: ~/.bitcoin)
  --bitcoin-cli /path/to/cli     Path to bitcoin-cli binary (default: bitcoin-cli)
  --remove-config                Also delete bitcoin.conf
  --yes                          Skip confirmation prompt
  --help                         Show this help
EOF
}

confirm() {
    if [ "$ASSUME_YES" -eq 1 ]; then
        return 0
    fi

    printf 'This will permanently delete regtest blockchain and wallet data under %s. Continue? [y/N] ' "$BITCOIN_DATA"
    read -r answer
    case "$answer" in
        y|Y|yes|YES)
            return 0
            ;;
        *)
            echo "Aborted."
            exit 1
            ;;
    esac
}

stop_bitcoind() {
    if ! pgrep -x bitcoind >/dev/null 2>&1; then
        echo "[*] bitcoind is not running"
        return 0
    fi

    echo "[*] Requesting clean shutdown via bitcoin-cli..."
    if "$BITCOIN_CLI" -datadir="$BITCOIN_DATA" -rpcuser="$RPC_USER" -rpcpassword="$RPC_PASSWORD" -regtest stop >/dev/null 2>&1; then
        for _ in {1..30}; do
            if ! pgrep -x bitcoind >/dev/null 2>&1; then
                echo "[+] bitcoind stopped cleanly"
                return 0
            fi
            sleep 1
        done

        echo "[!] bitcoind did not stop in time; sending TERM"
        pkill -TERM bitcoind >/dev/null 2>&1 || true
        for _ in {1..10}; do
            if ! pgrep -x bitcoind >/dev/null 2>&1; then
                echo "[+] bitcoind stopped"
                return 0
            fi
            sleep 1
        done
    else
        echo "[!] bitcoin-cli stop failed or RPC unavailable; sending TERM"
        pkill -TERM bitcoind >/dev/null 2>&1 || true
        for _ in {1..10}; do
            if ! pgrep -x bitcoind >/dev/null 2>&1; then
                echo "[+] bitcoind stopped"
                return 0
            fi
            sleep 1
        done
    fi

    echo "[!] bitcoind still running; sending KILL"
    pkill -KILL bitcoind >/dev/null 2>&1 || true
}

remove_path() {
    local path="$1"
    if [ -e "$path" ]; then
        echo "[*] Removing $path"
        rm -rf -- "$path"
    fi
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --bitcoin-data)
            BITCOIN_DATA="$2"
            shift 2
            ;;
        --bitcoin-cli)
            BITCOIN_CLI="$2"
            shift 2
            ;;
        --remove-config)
            REMOVE_CONFIG=1
            shift
            ;;
        --yes|-y)
            ASSUME_YES=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            exit 1
            ;;
    esac
done

if [ -z "$BITCOIN_DATA" ] || [ "$BITCOIN_DATA" = "/" ]; then
    echo "Refusing to clean an empty or root bitcoin data directory." >&2
    exit 1
fi

BITCOIN_DATA="${BITCOIN_DATA%/}"
BITCOIN_CONF="${BITCOIN_CONF:-$BITCOIN_DATA/bitcoin.conf}"
REGTEST_DIR="$BITCOIN_DATA/regtest"

confirm
stop_bitcoind

if [ ! -e "$BITCOIN_DATA" ]; then
    echo "[*] Bitcoin data directory does not exist: $BITCOIN_DATA"
    exit 0
fi

echo "[*] Removing regtest chain data from $REGTEST_DIR"
remove_path "$REGTEST_DIR"

if [ "$REMOVE_CONFIG" -eq 1 ]; then
    echo "[*] Removing Bitcoin config file $BITCOIN_CONF"
    remove_path "$BITCOIN_CONF"
fi

# Clean up obvious regtest leftovers that may exist at the top level in some installs.
for leftover in \
    "$BITCOIN_DATA/.cookie" \
    "$BITCOIN_DATA/.lock" \
    "$BITCOIN_DATA/mempool.dat" \
    "$BITCOIN_DATA/fee_estimates.dat"; do
    remove_path "$leftover"
done

echo "[+] Regtest cleanup complete"
echo "    Data removed: $REGTEST_DIR"
if [ "$REMOVE_CONFIG" -eq 1 ]; then
    echo "    Config removed: $BITCOIN_CONF"
else
    echo "    Config preserved: $BITCOIN_CONF"
fi






#!/usr/bin/env python3
"""
Autonomous Server Deployment Agent

This script allows an AI agent to deploy VPS servers on SporeStack
using funds from a Bitcoin HD wallet.

Usage:
    python agent_deploy.py --fund 10 --deploy
    python agent_deploy.py --check-balance
    python agent_deploy.py --list-servers
    python agent_deploy.py --seed "your twelve word seed phrase here"
"""

import argparse
import json
import sys
import os
from pathlib import Path

# Import our modules
from hd_wallet import HDWallet
from sporestack_deployer import SporeStackDeployer


def setup_wallet(seed=None, network="bitcoin"):
    """Setup HD wallet from seed or generate new one."""
    print("\n" + "="*60)
    print("WALLET SETUP")
    print("="*60)
    
    wallet = HDWallet(network=network, seed=seed)
    
    if seed is None:
        print("\n🔐 NEW WALLET CREATED!")
        print(f"\n📝 SEED PHRASE (SAVE THIS SECURELY!):")
        print(f"   {wallet.get_seed()}")
        print("\n⚠️  Store this seed phrase in a safe place!")
        print("   You'll need it to recover your funds.\n")
    else:
        print("\n✅ Wallet loaded from seed")
    
    print(f"📍 Address: {wallet.get_address()}")
    print(f"🔑 Private Key (WIF): {wallet.get_private_key()[:20]}...")
    
    return wallet


def check_wallet_balance(wallet):
    """Check and display wallet balance."""
    print("\n" + "="*60)
    print("WALLET BALANCE")
    print("="*60)
    
    try:
        balance_sat = wallet.get_balance()
        balance_btc = balance_sat / 100000000
        
        print(f"\n💰 Balance: {balance_btc:.8f} BTC ({balance_sat} satoshis)")
        
        if balance_sat == 0:
            print("\n⚠️  Wallet has no funds!")
            print(f"   Send Bitcoin to: {wallet.get_address()}")
        
        return balance_sat
    except Exception as e:
        print(f"\n❌ Error checking balance: {e}")
        print("   Make sure you have internet connection.")
        return 0


def fund_sporestack(wallet, amount_usd):
    """Fund a SporeStack token with wallet funds."""
    print("\n" + "="*60)
    print(f"FUNDING SPORESTACK TOKEN (${amount_usd})")
    print("="*60)
    
    deployer = SporeStackDeployer(wallet)
    
    try:
        token = deployer.fund_sporestack_token(amount_usd)
        print(f"\n✅ Token funded successfully!")
        print(f"   Token: {token[:30]}...")
        return deployer, token
    except Exception as e:
        print(f"\n❌ Error funding token: {e}")
        sys.exit(1)


def check_token_balance(deployer):
    """Check SporeStack token balance."""
    print("\n" + "="*60)
    print("SPORESTACK TOKEN BALANCE")
    print("="*60)
    
    try:
        balance = deployer.get_token_balance()
        print(f"\n💵 Token Balance: ${balance:.2f} USD")
        return balance
    except Exception as e:
        print(f"\n⚠️  No token found or error: {e}")
        return 0


def deploy_server(deployer, config):
    """Deploy a VPS server."""
    print("\n" + "="*60)
    print("DEPLOYING SERVER")
    print("="*60)
    
    print(f"\n🚀 Configuration:")
    for key, value in config.items():
        print(f"   {key}: {value}")
    
    try:
        server = deployer.deploy_server(**config)
        
        print("\n✅ SERVER DEPLOYED SUCCESSFULLY!")
        print(f"\n🖥️  Server Details:")
        print(f"   Machine ID: {server['machine_id']}")
        print(f"   Hostname: {server['hostname']}")
        print(f"   IPv4: {server['ipv4']}")
        if server.get('ipv6'):
            print(f"   IPv6: {server['ipv6']}")
        print(f"\n🔌 SSH Connection:")
        print(f"   ssh root@{server['ipv4']}")
        
        return server
    except Exception as e:
        print(f"\n❌ Error deploying server: {e}")
        sys.exit(1)


def list_servers(deployer):
    """List all deployed servers."""
    print("\n" + "="*60)
    print("DEPLOYED SERVERS")
    print("="*60)
    
    servers = deployer.list_servers()
    
    if not servers:
        print("\n   No servers deployed yet.")
        return
    
    for i, server in enumerate(servers, 1):
        print(f"\n{i}. {server['hostname']}")
        print(f"   Machine ID: {server['machine_id']}")
        print(f"   IPv4: {server['ipv4']}")
        print(f"   Provider: {server['provider']} ({server['region']})")
        print(f"   Flavor: {server['flavor']}")
        print(f"   OS: {server['operating_system']}")


def main():
    parser = argparse.ArgumentParser(
        description="Deploy VPS servers using Bitcoin wallet",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Wallet options
    parser.add_argument(
        '--seed',
        type=str,
        help='BIP39 seed phrase (generates new wallet if not provided)'
    )
    parser.add_argument(
        '--network',
        type=str,
        default='bitcoin',
        choices=['bitcoin', 'testnet'],
        help='Bitcoin network to use'
    )
    
    # Actions
    parser.add_argument(
        '--check-balance',
        action='store_true',
        help='Check wallet balance'
    )
    parser.add_argument(
        '--fund',
        type=float,
        metavar='AMOUNT',
        help='Fund SporeStack token with AMOUNT USD'
    )
    parser.add_argument(
        '--token-balance',
        action='store_true',
        help='Check SporeStack token balance'
    )
    parser.add_argument(
        '--deploy',
        action='store_true',
        help='Deploy a server'
    )
    parser.add_argument(
        '--list-servers',
        action='store_true',
        help='List deployed servers'
    )
    
    # Server configuration
    parser.add_argument(
        '--hostname',
        type=str,
        default='autoserver',
        help='Server hostname'
    )
    parser.add_argument(
        '--os',
        type=str,
        default='ubuntu-22-04',
        help='Operating system (e.g., ubuntu-22-04, debian-11, freebsd-14)'
    )
    parser.add_argument(
        '--flavor',
        type=str,
        default='vc2-1c-1gb',
        help='Server size (e.g., vc2-1c-1gb, vc2-2c-4gb)'
    )
    parser.add_argument(
        '--region',
        type=str,
        default='ewr',
        help='Region (e.g., ewr, lax, ams, ord)'
    )
    parser.add_argument(
        '--provider',
        type=str,
        default='vultr',
        help='Cloud provider (e.g., vultr, digitalocean)'
    )
    parser.add_argument(
        '--days',
        type=int,
        default=30,
        help='Number of days to run the server'
    )
    parser.add_argument(
        '--autorenew',
        action='store_true',
        help='Auto-renew server from token balance'
    )
    parser.add_argument(
        '--ssh-key',
        type=str,
        help='Path to SSH public key file'
    )
    
    args = parser.parse_args()
    
    # Setup wallet
    wallet = setup_wallet(seed=args.seed, network=args.network)
    
    # Check balance if requested or if funding
    if args.check_balance or args.fund:
        balance = check_wallet_balance(wallet)
    
    # Initialize deployer
    deployer = SporeStackDeployer(wallet)
    
    # Fund token if requested
    if args.fund:
        deployer, token = fund_sporestack(wallet, args.fund)
    
    # Check token balance
    if args.token_balance:
        check_token_balance(deployer)
    
    # Deploy server
    if args.deploy:
        server_config = {
            'hostname': args.hostname,
            'operating_system': args.os,
            'flavor': args.flavor,
            'region': args.region,
            'provider': args.provider,
            'days': args.days,
            'autorenew': args.autorenew,
            'ssh_key_file': args.ssh_key
        }
        deploy_server(deployer, server_config)
    
    # List servers
    if args.list_servers:
        list_servers(deployer)
    
    print("\n" + "="*60)
    print("DONE")
    print("="*60 + "\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
#!/usr/bin/env python3
import argparse
import subprocess
import sys
import os

def run_command(cmd, password=None):
    if password:
        # Check if sshpass is installed
        if subprocess.run(["which", "sshpass"], stdout=subprocess.DEVNULL).returncode != 0:
            print("[-] Error: sshpass is not installed. Please install it (sudo apt install sshpass) or use key-based auth.")
            sys.exit(1)
        
        full_cmd = ["sshpass", "-p", password] + cmd
    else:
        full_cmd = cmd
        
    print(f"[*] Running: {' '.join(full_cmd)}")
    try:
        # Run interactively so user can see output/errors
        subprocess.run(full_cmd)
    except KeyboardInterrupt:
        print("\n[*] Stopping tunnel...")

def main():
    parser = argparse.ArgumentParser(description="SSH Tunnel Tool for ICS Pivoting")
    parser.add_argument("--ssh-host", required=True, help="Jump host IP/Hostname")
    parser.add_argument("--ssh-user", required=True, help="SSH Username")
    parser.add_argument("--ssh-pass", help="SSH Password (optional, uses sshpass)")
    parser.add_argument("--ssh-key", help="SSH Private Key (optional)")
    parser.add_argument("--ssh-port", default="22", help="SSH Port (default: 22)")
    
    subparsers = parser.add_subparsers(dest="mode", required=True)
    
    # Local Port Forwarding
    # ssh -L local_port:target_ip:target_port user@host
    local_parser = subparsers.add_parser("local", help="Local Port Forwarding (-L)")
    local_parser.add_argument("--local-port", required=True, help="Local listening port")
    local_parser.add_argument("--target-ip", required=True, help="Internal target IP")
    local_parser.add_argument("--target-port", required=True, help="Internal target Port")

    # Dynamic SOCKS Proxy
    # ssh -D local_port user@host
    socks_parser = subparsers.add_parser("socks", help="Dynamic SOCKS Proxy (-D)")
    socks_parser.add_argument("--local-port", default="1080", help="Local SOCKS port (default: 1080)")

    args = parser.parse_args()

    # Base SSH command
    ssh_cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-p", args.ssh_port]
    
    if args.ssh_key:
        ssh_cmd.extend(["-i", args.ssh_key])
        
    # Mode specific args
    if args.mode == "local":
        ssh_cmd.extend(["-L", f"{args.local_port}:{args.target_ip}:{args.target_port}"])
        ssh_cmd.extend(["-N"]) # Do not execute remote command
    elif args.mode == "socks":
        ssh_cmd.extend(["-D", args.local_port])
        ssh_cmd.extend(["-N"]) # Do not execute remote command

    # Target user@host
    ssh_cmd.append(f"{args.ssh_user}@{args.ssh_host}")

    run_command(ssh_cmd, password=args.ssh_pass)

if __name__ == "__main__":
    main()

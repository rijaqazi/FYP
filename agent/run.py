#!/usr/bin/env python3
import subprocess
import time
import os
import signal
from pathlib import Path
import socket

def start_server(name, command, working_dir, port=None, wait_time=4):
    print(f"\n Starting {name}...")
    try:

        original_dir = os.getcwd()
        os.chdir(working_dir)
        

        proc = subprocess.Popen(command, shell=True, preexec_fn=os.setsid)
        time.sleep(wait_time)  
        

        os.chdir(original_dir)
        
        print(f"[+] {name} started successfully (PID: {proc.pid}).")
        if port:
            print(f" Access: http://127.0.0.1:{port}/")
            print(f"   Username: admin")
            print(f"   Password: password123")
        return proc
    except Exception as e:
        print(f"[x] Failed to start {name}: {e}")
        return None

if __name__ == "__main__":
    print("==============================")
    print("Starting All FITPoolChain Servers...")
    print("==============================\n")

    BASE_DIR = Path("/home/defender/Desktop")
    

    print(f"\n Starting MongoDB Server...")
    mongodb_proc = subprocess.Popen(
        ["mongod", "--dbpath", "/home/defender/mongodb/data"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid
    )
    time.sleep(3)
    print(f"[+] MongoDB Server started successfully (PID: {mongodb_proc.pid}).")


    rules_dir = BASE_DIR / "Rule_Generation"
    rules_proc = start_server(
        "Secure Server (Rules & Reports)", 
        "python3 secure_server.py",
        rules_dir,
        port=5000,
        wait_time=5
    )

 
    heartbeat_dir = BASE_DIR / "agent"
    heartbeat_proc = start_server(
        "Heartbeat Server", 
        "python3 heartbeat_server.py",
        heartbeat_dir,
        port=5001,
        wait_time=3
    )


    ioc_dir = BASE_DIR / "ioc"
    ioc_proc = start_server(
        "IOC Flask Server", 
        "python3 taxi_server.py",
        ioc_dir,
        port=5002,
        wait_time=4
    )


    print("\n" + "="*50)
    print("[!] ALL SERVERS STARTED SUCCESSFULLY!")
    print("="*50)
    print("\n Access URLs:")
    print("   - Secure Server (Rules/Reports): http://127.0.0.1:5005/ (redirects to /discover)")
    print("   - Heartbeat Server:              http://127.0.0.1:5001/")
    print("   - IOC Flask Server:              http://127.0.0.1:5002/")
    print("\n Login Credentials (for all servers):")
    print("   Username: admin")
    print("   Password: password123")
    print("\n Running Services:")
    print("    MongoDB Server")
    print("    Secure Server (Rules & Reports)")
    print("    Heartbeat Server")
    print("    IOC Flask Server")
  
    print("\n Press Ctrl+C to stop all servers.")
    print("="*50 + "\n")

    try:
        
        while True:
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n Shutting down all servers...")

        processes = [rules_proc, heartbeat_proc, ioc_proc, agent_proc, mongodb_proc]
        for p in processes:
            if p and p.poll() is None:  
                try:

                    os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                    p.wait(timeout=5)
                    print(f" Terminated process {p.pid}")
                except subprocess.TimeoutExpired:
                    print(f" Process {p.pid} did not terminate gracefully, forcing kill...")
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)  # Force kill
                except Exception as e:
                    print(f"[x] Error terminating process {p.pid}: {e}")
        
        for port in [5000, 5001, 5002]:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind(("127.0.0.1", port))
                print(f"[!] Port {port} is now free.")
            except socket.error:
                print(f"[x] Port {port} is still in use. Please manually kill the process.")
            finally:
                s.close()
        
        print("[!!]All servers stopped.")

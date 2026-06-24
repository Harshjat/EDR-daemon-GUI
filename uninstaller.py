import os
import sys
import ctypes
import shutil
import winreg
import subprocess
import time

# Define our secure industry-grade paths
PROGRAM_FILES_DIR = os.path.join(os.environ.get("PROGRAMFILES", "C:\\Program Files"), "EDR_Agent")
PROGRAM_DATA_DIR = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "EDR_Agent")

def is_admin():
    """Check if the script is running with Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    """Force Windows to show the UAC prompt to elevate privileges."""
    print("Requesting Administrative privileges...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

def uninstall():
    print("--- EDR Agent Surgical Uninstaller ---")
    
    # 1. Kill User-Mode Processes
    # We use Windows Management Instrumentation (WMIC) to find our specific python scripts and kill them.
    # This prevents us from accidentally killing ALL python.exe processes on the machine.
    print("[*] Terminating User-Mode UI processes...")
    subprocess.run('wmic process where "commandline like \'%tray_controller.py%\'" call terminate', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run('wmic process where "commandline like \'%gui_viewer.py%\'" call terminate', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # 2. Stop the Windows Service
    print("[*] Sending STOP signal to EDRAgentService...")
    # 'sc' is the native Windows Service Control command-line tool.
    subprocess.run(["sc", "stop", "EDRAgentService"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # Give the service 3 seconds to flush its logs and spin down gracefully.
    print("[*] Waiting for daemon to release file locks...")
    time.sleep(3) 
    
    # 3. Unregister the Windows Service
    print("[*] Deleting EDRAgentService from Windows Registry...")
    subprocess.run(["sc", "delete", "EDRAgentService"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    
    # 4. Remove User Persistence from Registry
    print("[*] Scrubbing HKCU Run Registry Key...")
    try:
        registry_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_ALL_ACCESS)
        winreg.DeleteValue(key, "EDRAgentUI")
        winreg.CloseKey(key)
        print("    -> Registry key EDRAgentUI removed.")
    except FileNotFoundError:
        # If it doesn't exist, it was already removed or never injected.
        print("    -> Registry key already gone.")
    except Exception as e:
        print(f"    [!] Non-critical error removing registry key: {e}")

    # 5. Wipe Physical Directories
    print("[*] Wiping application binaries from Program Files...")
    if os.path.exists(PROGRAM_FILES_DIR):
        try:
            shutil.rmtree(PROGRAM_FILES_DIR)
            print("    -> Program Files directory deleted.")
        except Exception as e:
            print(f"    [!] Could not delete {PROGRAM_FILES_DIR}: {e}")
    else:
        print("    -> Directory already gone.")

    print("[*] Wiping agent logs from ProgramData...")
    if os.path.exists(PROGRAM_DATA_DIR):
        try:
            shutil.rmtree(PROGRAM_DATA_DIR)
            print("    -> ProgramData directory deleted.")
        except Exception as e:
            print(f"    [!] Could not delete {PROGRAM_DATA_DIR}: {e}")
    else:
        print("    -> Directory already gone.")

    print("\n[+] EDR Agent has been completely removed from the system.")

if __name__ == "__main__":
    if not is_admin():
        run_as_admin()
    else:
        # Added a safety prompt so you don't accidentally wipe it by misclicking
        print("WARNING: This will completely remove the EDR Agent and all logs.")
        confirm = input("Are you sure you want to proceed? (Y/N): ")
        if confirm.strip().upper() == 'Y':
            uninstall()
        else:
            print("Uninstall cancelled.")
        
        input("\nPress Enter to exit...")
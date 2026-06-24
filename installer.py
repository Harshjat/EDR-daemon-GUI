import os
import sys
import ctypes
import shutil
import subprocess
import winreg

# The directory where the user downloaded/extracted the code
INSTALLER_DIR = os.path.dirname(os.path.abspath(__file__))

# The target system directories
PROGRAM_FILES_DIR = os.path.join(os.environ.get("PROGRAMFILES", "C:\\Program Files"), "EDR_Agent")
PROGRAM_DATA_DIR = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "EDR_Agent")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    print("Requesting Administrative privileges...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

def install():
    print("--- EDR Agent Master Installer ---")
    
    # 1. Create Directories
    print(f"[*] Building system directories...")
    os.makedirs(PROGRAM_DATA_DIR, exist_ok=True)
    os.makedirs(PROGRAM_FILES_DIR, exist_ok=True)
    
    # 2. Copy All Core Components
    # We leave the uninstaller.py and installer.py in the download folder.
    # The actual working files go into Program Files.
    files_to_install = [
        "daemon_core.py", 
        "service_wrapper.py", 
        "gui_viewer.py", 
        "tray_controller.py"
    ]
    
    print("[*] Copying binaries to Program Files...")
    for file_name in files_to_install:
        source_path = os.path.join(INSTALLER_DIR, file_name)
        dest_path = os.path.join(PROGRAM_FILES_DIR, file_name)
        
        if os.path.exists(source_path):
            shutil.copy(source_path, dest_path)
            print(f"    -> Copied {file_name}")
        else:
            print(f"\n[!] CRITICAL ERROR: Missing {file_name}.")
            print("[!] Ensure all agent scripts are in the same folder as this installer.")
            input("\nPress Enter to exit...")
            sys.exit(1)
            
    # 3. Register and Start the Background Service
    print("\n[*] Registering Windows Service (Session 0)...")
    service_script = os.path.join(PROGRAM_FILES_DIR, "service_wrapper.py")
    try:
        subprocess.check_call([sys.executable, service_script, "--startup", "auto", "install"])
        subprocess.check_call([sys.executable, service_script, "start"])
        print("    -> Service installed and running.")
    except subprocess.CalledProcessError as e:
        print(f"\n[!] Failed to install service. Error: {e}")
        print("[!] Ensure pywin32 is installed: pip install pywin32")
        sys.exit(1)

    # 4. Inject User Registry Key for Boot Persistence
    print("\n[*] Configuring User-Mode Persistence (Session 1)...")
    try:
        pythonw_exe = sys.executable.replace("python.exe", "pythonw.exe")
        tray_script_dest = os.path.join(PROGRAM_FILES_DIR, "tray_controller.py")
        startup_command = f'"{pythonw_exe}" "{tray_script_dest}"'
        
        registry_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_ALL_ACCESS)
        winreg.SetValueEx(key, "EDRAgentUI", 0, winreg.REG_SZ, startup_command)
        winreg.CloseKey(key)
        print("    -> HKCU Run Key injected successfully.")
    except Exception as e:
        print(f"    [!] Failed to inject registry key: {e}")

    # 5. Launch the Tray Icon immediately
    print("\n[*] Launching User Interface...")
    subprocess.Popen(startup_command, shell=True)

    print("\n[+] INSTALLATION COMPLETE.")
    print("[+] The Agent is now running securely in the background.")
    print("[+] Check your System Tray for the Blue EDR Icon.")

if __name__ == "__main__":
    if not is_admin():
        run_as_admin()
    else:
        try:
            install()
        except Exception as e:
            print(f"\n[!] Unhandled exception during installation: {e}")
        
        input("\nPress Enter to exit...")
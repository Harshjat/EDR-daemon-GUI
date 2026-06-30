import wmi
import sys
import hashlib
import os

def get_file_hash(file_path):
    """
    WHAT: Calculates the SHA-256 hash of an executable file on disk.
    WHY: To cryptographically identify the binary, ignoring its filename.
    HOW: Reads the file in 4KB chunks so we don't consume massive amounts of RAM.
    """
    if file_path == "PATH_UNKNOWN" or not os.path.exists(file_path):
        return "HASH_UNAVAILABLE"
        
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        # Edge Case: Windows or an Antivirus might hold an exclusive lock on the file as it launches
        return "HASH_FAILED_LOCKED"

def main():
    print("--- EDR Sensor Test: WMI Process Watcher ---")
    print("[*] Initializing WMI connection to the local OS...")
    
    try:
        # HOW: Initialize the WMI COM object. This connects our Python script 
        # to the Windows Management Instrumentation service.
        c = wmi.WMI()
        
        # WHAT: We subscribe to a specific Windows Event.
        # wmi_class="Win32_Process" tells Windows we only care about processes.
        # notification_type="Creation" means we only want to know when they start, not when they close.
        process_watcher = c.watch_for(
            notification_type="Creation", 
            wmi_class="Win32_Process"
        )
        
        print("[+] WMI Subscription Active. Listening for new processes...")
        print("[*] Open Notepad, Calculator, or CMD to see the events fire.\n")
        
        # The Infinite Event Loop
        while True:
            # HOW: process_watcher() is a BLOCKING call. 
            # This is the magic of Pub/Sub. The script completely pauses on this exact line. 
            # It uses 0% CPU. It only wakes up when the Windows Kernel hands it a new process object.
            new_process = process_watcher()
            
            # --- CONTEXTUAL EXTRACTION ---
            # When the OS wakes us up, we extract the 5 Fatal Identifiers.
            
            # 1. Process Name
            proc_name = new_process.Name
            
            # 2. Process ID (PID)
            pid = new_process.ProcessId
            
            # 3. Parent Process ID (PPID)
            # WMI returns this as ParentProcessId
            ppid = new_process.ParentProcessId
            
            # 4. Command Line
            # Edge Case: Sometimes a process is restricted (like an Antivirus process), 
            # and Windows denies us permission to read its command line. We must handle the 'None' type.
            cmd_line = new_process.CommandLine if new_process.CommandLine else "ACCESS_DENIED_OR_EMPTY"
            
            # 5. File Path (Your addition)
            # WMI stores the physical disk path in 'ExecutablePath'
            file_path = new_process.ExecutablePath if new_process.ExecutablePath else "PATH_UNKNOWN"
            
            # --- NEW: THE ENRICHMENT ENGINE ---
            # 6. Cryptographic Hash
            file_hash = get_file_hash(file_path)
            
            # Display the intercepted data
            print(f"[ALERT] New Process Detected: {proc_name} (PID: {pid})")
            print(f"   ├─ Parent PID : {ppid}")
            print(f"   ├─ File Path  : {file_path}")
            print(f"   ├─ SHA-256    : {file_hash}")
            print(f"   └─ Command    : {cmd_line}\n")
            
    except KeyboardInterrupt:
        print("\n[*] Sensor test stopped by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] WMI Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
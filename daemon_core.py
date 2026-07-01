import os
import sys
import time
import json
import hashlib
import threading
from datetime import datetime
import wmi
import pythoncom  # <--- NEW: Required for Windows Services to speak to COM/WMI

# --- CONFIGURATION (INDUSTRY GRADE) ---
PROGRAM_DATA_DIR = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "EDR_Agent")
# We rename the log to reflect that it is now structured telemetry, not just heartbeats
LOG_FILE = os.path.join(PROGRAM_DATA_DIR, "agent_telemetry.log")

def ensure_directories():
    """Ensure system-wide directories exist before writing."""
    if not os.path.exists(PROGRAM_DATA_DIR):
        os.makedirs(PROGRAM_DATA_DIR, exist_ok=True)

def get_file_hash(file_path):
    """Calculates the SHA-256 hash of an executable file on disk."""
    if file_path == "PATH_UNKNOWN" or not os.path.exists(file_path):
        return "HASH_UNAVAILABLE"
        
    try:
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return "HASH_FAILED_LOCKED"

def write_telemetry(event_data):
    """
    WHAT: Safely writes a JSON object to the log file and forces it to physical disk.
    """
    try:
        ensure_directories()
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            # Convert the Python dictionary into a JSON string
            json_string = json.dumps(event_data)
            
            # Write, flush memory, and force OS disk sync
            f.write(json_string + "\n")
            f.flush()
            os.fsync(f.fileno())
    except PermissionError:
        # If the GUI is reading, drop the log to prevent a crash. 
        # (In a true enterprise EDR, we would queue this in RAM and retry).
        pass
    except Exception:
        pass

def agent_worker_loop(stop_event):
    """
    WHAT: The true headless daemon worker that intercepts WMI events.
    """
    # --- THE CRITICAL OS FIX: COM INITIALIZATION ---
    # We must explicitly tell the Windows Kernel to allow this specific 
    # background thread to interact with the COM subsystem.
    pythoncom.CoInitialize() 
    
    try:
        try:
            # Initialize WMI connection
            c = wmi.WMI()
            process_watcher = c.watch_for(notification_type="Creation", wmi_class="Win32_Process")
        except Exception as e:
            # If WMI fails (very rare), we log an error payload and exit the thread
            write_telemetry({"error": f"WMI Initialization Failed: {e}", "timestamp": datetime.now().isoformat()})
            return

        # Run until the Service Control Manager (SCM) triggers the stop_event
        while not stop_event.is_set():
            try:
                # HOW: timeout_ms=2000 prevents a Thread Deadlock.
                # It waits 2 seconds for a process. If none start, it throws x_wmi_timed_out.
                new_process = process_watcher(timeout_ms=2000)
                
                # --- CONTEXTUAL EXTRACTION ---
                file_path = new_process.ExecutablePath if new_process.ExecutablePath else "PATH_UNKNOWN"
                
                # Construct the SIEM-ready JSON Payload
                telemetry_payload = {
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "ProcessCreate",
                    "process_name": new_process.Name,
                    "pid": new_process.ProcessId,
                    "ppid": new_process.ParentProcessId,
                    "file_path": file_path,
                    "sha256": get_file_hash(file_path),
                    "command_line": new_process.CommandLine if new_process.CommandLine else "ACCESS_DENIED_OR_EMPTY"
                }
                
                # Save the JSON payload to disk
                write_telemetry(telemetry_payload)
                
            except wmi.x_wmi_timed_out:
                # No process started in the last 2 seconds. 
                # We simply 'pass' so the while loop can check if stop_event is set.
                pass
            except Exception as e:
                # Handle unexpected WMI parsing errors safely
                time.sleep(1)
    finally:
        # We must cleanly release the COM resources back to Windows when the service stops
        pythoncom.CoUninitialize()

def main():
    """Fallback entry point if run directly instead of via the Service Wrapper."""
    ensure_directories()
    stop_event = threading.Event()
    try:
        agent_worker_loop(stop_event)
    except KeyboardInterrupt:
        stop_event.set()

if __name__ == "__main__":
    main()
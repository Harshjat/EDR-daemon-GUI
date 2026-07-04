import os
import sys
import time
import json
import hashlib
import threading
from datetime import datetime
import wmi
import pythoncom
import psutil  # Required for the Network Sensor
import win32file
import win32con

FILE_LIST_DIRECTORY = 0x0001
FIM_ACTION_MAP = {
    1: "[CREATED]",
    2: "[DELETED]",
    3: "[MODIFIED]",
    4: "[RENAMED FROM]",
    5: "[RENAMED TO]"
}

# --- CONFIGURATION (INDUSTRY GRADE) ---
PROGRAM_DATA_DIR = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "EDR_Agent")
LOG_FILE = os.path.join(PROGRAM_DATA_DIR, "agent_telemetry.log")

# --- THE MUTEX (Thread Lock) ---
# Prevents the Process thread and Network thread from corrupting the JSON log
# if they try to write at the exact same millisecond.
FILE_LOCK = threading.Lock()

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
        
        # HOW: We grab the Mutex before opening the file. 
        # If another thread is writing, this thread waits here patiently.
        with FILE_LOCK:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                json_string = json.dumps(event_data)
                f.write(json_string + "\n")
                f.flush()
                os.fsync(f.fileno())
    except PermissionError:
        pass
    except Exception:
        pass

def agent_worker_loop(stop_event):
    """
    WHAT: The true headless daemon worker that intercepts WMI Process events.
    """
    pythoncom.CoInitialize() 
    try:
        try:
            c = wmi.WMI()
            process_watcher = c.watch_for(notification_type="Creation", wmi_class="Win32_Process")
        except Exception as e:
            write_telemetry({"error": f"WMI Initialization Failed: {e}", "timestamp": datetime.now().isoformat()})
            return

        while not stop_event.is_set():
            try:
                new_process = process_watcher(timeout_ms=2000)
                file_path = new_process.ExecutablePath if new_process.ExecutablePath else "PATH_UNKNOWN"
                
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
                write_telemetry(telemetry_payload)
                
            except wmi.x_wmi_timed_out:
                pass
            except Exception as e:
                time.sleep(1)
    finally:
        pythoncom.CoUninitialize()

def network_worker_loop(stop_event):
    """
    WHAT: The Differential Network Sensor thread.
    """
    known_connections = set()
    
    while not stop_event.is_set():
        try:
            current_snapshot = set()
            
            for conn in psutil.net_connections(kind='inet'):
                status = conn.status
                if not status or status == "NONE":
                    continue
                
                pid = conn.pid if conn.pid else 0
                proto = "TCP" if conn.type == 1 else "UDP"
                laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "UNKNOWN"
                raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "0.0.0.0:0"
                
                fingerprint = f"{pid}_{proto}_{laddr}_{raddr}_{status}"
                current_snapshot.add(fingerprint)
                
                if fingerprint not in known_connections:
                    telemetry_payload = {
                        "timestamp": datetime.now().isoformat(),
                        "event_type": "NetworkConnection",
                        "pid": pid,
                        "protocol": proto,
                        "local_address": laddr,
                        "remote_address": raddr,
                        "status": status
                    }
                    write_telemetry(telemetry_payload)
                    known_connections.add(fingerprint)
            
            # Garbage Collection
            known_connections = current_snapshot
            
            # Pause 1 second, but break immediately if Admin stops the service
            stop_event.wait(1)
            
        except Exception:
            time.sleep(1)

def fim_worker_loop(stop_event):
    """
    WHAT: File Integrity Monitoring (FIM) Sensor Thread.
    """
    target_dir = "C:\\Users\\Public"
    if not os.path.exists(target_dir):
        os.makedirs(target_dir, exist_ok=True)
        
    try:
        # Acquire Directory Handle
        hDir = win32file.CreateFile(
            target_dir,
            FILE_LIST_DIRECTORY,
            win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
            None,
            win32con.OPEN_EXISTING,
            win32con.FILE_FLAG_BACKUP_SEMANTICS,
            None
        )
    except Exception as e:
        write_telemetry({"error": f"FIM Init Failed: {e}", "timestamp": datetime.now().isoformat()})
        return

    change_filters = (
        win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
        win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
        win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
        win32con.FILE_NOTIFY_CHANGE_SIZE |
        win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
        win32con.FILE_NOTIFY_CHANGE_SECURITY
    )

    while not stop_event.is_set():
        try:
            # Blocking API call. Because this thread is daemon=True, 
            # the OS will safely kill it when the service shuts down.
            results = win32file.ReadDirectoryChangesW(
                hDir, 8192, True, change_filters, None, None
            )
            
            # Use FILE_LOCK automatically via write_telemetry
            for action_code, file_name in results:
                action_str = FIM_ACTION_MAP.get(action_code, f"UNKNOWN:{action_code}")
                full_path = os.path.join(target_dir, file_name)
                
                telemetry_payload = {
                    "timestamp": datetime.now().isoformat(),
                    "event_type": "FileEvent",
                    "action": action_str,
                    "file_path": full_path
                }
                write_telemetry(telemetry_payload)
        except Exception:
            time.sleep(1)
            
    win32file.CloseHandle(hDir)

def start_sensors(stop_event):
    """
    WHAT: Master function to spawn all sensor threads.
    WHY: Keeps the service_wrapper clean and decoupled from the number of sensors.
    """
    proc_thread = threading.Thread(target=agent_worker_loop, args=(stop_event,), daemon=True)
    net_thread = threading.Thread(target=network_worker_loop, args=(stop_event,), daemon=True)
    fim_thread = threading.Thread(target=fim_worker_loop, args=(stop_event,), daemon=True)
    
    proc_thread.start()
    net_thread.start()
    fim_thread.start()
    
    return [proc_thread, net_thread, fim_thread]

def main():
    """Fallback entry point if run directly."""
    ensure_directories()
    stop_event = threading.Event()
    try:
        threads = start_sensors(stop_event)
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        for t in threads:
            t.join()

if __name__ == "__main__":
    main()
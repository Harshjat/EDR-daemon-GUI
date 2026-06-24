import time
import os
import sys
from datetime import datetime
import threading
# --- removed pystray and PIL as a true system daemon cannot have a UI ---

# --- CONFIGURATION (INDUSTRY GRADE) ---
# System-wide services store binaries in Program Files, but MUST write data to ProgramData.
PROGRAM_DATA_DIR = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "EDR_Agent")
LOG_FILE = os.path.join(PROGRAM_DATA_DIR, "agent_heartbeat.log")

def ensure_directories():
    """Ensure system-wide directories exist before writing."""
    if not os.path.exists(PROGRAM_DATA_DIR):
        os.makedirs(PROGRAM_DATA_DIR, exist_ok=True)

def write_heartbeat():
    """
    WHAT: Opens the log file, writes a timestamped message, and forces it to disk.
    WHEN: Called every 5 seconds by the main infinite loop.
    WHY: To prove the agent is alive and functioning (a 'heartbeat').
    """
    try:
        # HOW: We use the 'with' statement (context manager). 
        # WHY: It guarantees that the file handle is automatically and safely closed 
        # the moment we are done with it, even if an error occurs inside the block.
        # We use mode "a" (append) so we don't overwrite previous logs.
        ensure_directories() # Ensure path exists before opening
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            
            # Generate a human-readable timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{timestamp}] Agent Heartbeat: System is secure and monitoring active.\n"
            
            # Write the string to Python's internal memory buffer.
            # NOTE: At this exact line, the data is NOT on the hard drive yet!
            f.write(log_entry)
            
            # --- THE CRITICAL EDR/DAEMON STEPS ---
            
            # 1. Force Python to push the data out of its internal memory buffer to the Windows OS.
            f.flush() 
            
            # 2. Force Windows to push the data from its OS-level disk cache directly to the physical hard drive.
            # WHY: If a user pulls the power plug right now, the log is already permanently saved.
            os.fsync(f.fileno())

    # WHAT & WHY: Defensive Programming.
    # If our future GUI has the file locked to read it, Windows might block us from writing.
    # Instead of the background agent crashing silently, we catch the PermissionError,
    # ignore it for this specific 5-second cycle, and try again on the next loop.
    except PermissionError:
        pass 
        
    # Catch any other unforeseen errors (e.g., hard drive is completely full)
    except Exception as e:
        # In a real EDR, we might write this to the Windows Event Viewer.
        # For now, we pass to ensure the infinite loop NEVER dies.
        pass
def agent_worker_loop(stop_event: threading.Event, interval_seconds: float = 5.0):
    """Run the daemon heartbeat loop until the stop event is signaled."""
    while not stop_event.is_set():
        write_heartbeat()
        # Wait for the next heartbeat or exit immediately if stop_event is set.
        stop_event.wait(interval_seconds)
def main():
    """
    WHAT: The true headless daemon entry point.
    """
    print(f"Starting EDR Core Engine. Logging to: {LOG_FILE}")
    ensure_directories()
    
    # In a true Windows Service, the service manager tells us when to stop.
    # For now, as a headless script, we run until the process is killed.
    stop_event = threading.Event()
    
    try:
        # We run the worker loop directly on the main thread now, 
        # because we no longer have a Windows UI Message Loop to block.
        agent_worker_loop(stop_event)
    except KeyboardInterrupt:
        print("\nAgent stopped by Admin.")
        stop_event.set()

if __name__ == "__main__":
    main()
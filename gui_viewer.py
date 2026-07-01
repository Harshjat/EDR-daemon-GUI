import tkinter as tk
from tkinter import ttk
import os
import json

# Define the system path
PROGRAM_DATA_DIR = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "EDR_Agent")
LOG_FILE = os.path.join(PROGRAM_DATA_DIR, "agent_telemetry.log")

class EDRDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("EDR Agent - Threat Hunting Dashboard")
        self.root.geometry("1200x600")
        self.root.configure(bg="#1e1e1e")
        
        # We track the last read line so we don't re-parse the entire file every 2 seconds
        self.last_line_index = 0

        # Create a visual header
        header = tk.Label(self.root, text="Live Process Telemetry (Session 0 -> Session 1 IPC)", 
                          bg="#1e1e1e", fg="#00ff00", font=("Consolas", 14, "bold"))
        header.pack(pady=10)

        # Create the Table (Treeview)
        columns = ("Time", "Process", "PID", "PPID", "Path", "SHA-256", "Command Line")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=20)
        
        # Configure Column Widths and Headings
        widths = [140, 150, 70, 70, 250, 200, 300]
        for col, width in zip(columns, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="w")

        # Add a scrollbar
        scrollbar = ttk.Scrollbar(self.root, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(padx=10, pady=10, expand=True, fill='both')

        # Define Threat Intelligence Color Tags
        self.tree.tag_configure('suspicious_red', background='#4a0000', foreground='white')
        self.tree.tag_configure('warning_yellow', background='#4a4a00', foreground='white')
        self.tree.tag_configure('normal', background='#1e1e1e', foreground='#d4d4d4')

        # Start the telemetry polling loop
        self.refresh_logs()

    def evaluate_threat_level(self, process_name, file_path):
        """Basic Threat Intel Logic to color-code the dashboard."""
        process_name = process_name.lower()
        file_path = file_path.lower()

        # High Suspicion (Red)
        if "path_unknown" in file_path or "\\appdata\\" in file_path or "\\temp\\" in file_path:
            return 'suspicious_red'
        
        # Medium Suspicion - "Living off the Land" Binaries (Yellow)
        if process_name in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'certutil.exe']:
            return 'warning_yellow'
        
        return 'normal'

    def refresh_logs(self):
        """Reads only the NEW lines from the JSON log and populates the table."""
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                    # Only process lines we haven't seen yet
                    if len(lines) > self.last_line_index:
                        new_lines = lines[self.last_line_index:]
                        
                        for line in new_lines:
                            try:
                                data = json.loads(line.strip())
                                
                                # Format the time for better readability
                                time_str = data.get("timestamp", "").split("T")[-1][:8]
                                
                                row_data = (
                                    time_str,
                                    data.get("process_name", ""),
                                    data.get("pid", ""),
                                    data.get("ppid", ""),
                                    data.get("file_path", ""),
                                    data.get("sha256", "HASH_UNAVAILABLE")[:16] + "...", # Truncate hash for UI
                                    data.get("command_line", "")
                                )
                                
                                # Evaluate Threat Color
                                tag = self.evaluate_threat_level(data.get("process_name", ""), data.get("file_path", ""))
                                
                                # Insert at the bottom of the table
                                self.tree.insert("", tk.END, values=row_data, tags=(tag,))
                                
                            except json.JSONDecodeError:
                                pass # Ignore incomplete writes
                                
                        # Auto-scroll to the bottom
                        # self.tree.yview_moveto(1)
                        
                        # Update our tracker
                        self.last_line_index = len(lines)
                        
            except PermissionError:
                pass # Safe failure if daemon is writing

        # Schedule the next check in 2 seconds
        self.root.after(2000, self.refresh_logs)

if __name__ == "__main__":
    # Style configurations for a modern dark theme
    root = tk.Tk()
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("Treeview", background="#1e1e1e", foreground="#d4d4d4", fieldbackground="#1e1e1e", rowheight=25)
    style.map('Treeview', background=[('selected', '#005599')])
    style.configure("Treeview.Heading", background="#333333", foreground="white", font=('Consolas', 10, 'bold'))
    
    app = EDRDashboard(root)
    root.mainloop()
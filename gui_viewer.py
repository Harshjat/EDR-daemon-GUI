import tkinter as tk
from tkinter import ttk
import os
import json

PROGRAM_DATA_DIR = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "EDR_Agent")
LOG_FILE = os.path.join(PROGRAM_DATA_DIR, "agent_telemetry.log")

class EDRDashboard:
    def __init__(self, root):
        self.root = root
        self.root.title("EDR Agent - Threat Hunting Dashboard")
        self.root.geometry("1200x600")
        self.root.configure(bg="#1e1e1e")
        self.last_line_index = 0

        header = tk.Label(self.root, text="Live System Telemetry (Process & Network)", 
                          bg="#1e1e1e", fg="#00ff00", font=("Consolas", 14, "bold"))
        header.pack(pady=10)

        columns = ("Time", "Process", "PID", "PPID", "Path", "SHA-256", "Command Line")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=20)
        
        widths = [140, 150, 70, 70, 250, 200, 300]
        for col, width in zip(columns, widths):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=width, anchor="w")

        scrollbar = ttk.Scrollbar(self.root, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.pack(padx=10, pady=10, expand=True, fill='both')

        self.tree.tag_configure('suspicious_red', background='#4a0000', foreground='white')
        self.tree.tag_configure('warning_yellow', background='#4a4a00', foreground='white')
        self.tree.tag_configure('normal', background='#1e1e1e', foreground='#d4d4d4')
        self.tree.tag_configure('network_blue', background='#002244', foreground='#88ccff') # Network Color
        self.tree.tag_configure('file_purple', background='#30004a', foreground='#dca3ff') # FIM Color
        self.tree.tag_configure('registry_orange', background='#4a2500', foreground='#ffb366') # RIM Color

        self.refresh_logs()

    def evaluate_threat_level(self, process_name, file_path):
        process_name = process_name.lower()
        file_path = file_path.lower()

        if "path_unknown" in file_path or "\\appdata\\" in file_path or "\\temp\\" in file_path:
            return 'suspicious_red'
        if process_name in ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'certutil.exe']:
            return 'warning_yellow'
        return 'normal'

    def refresh_logs(self):
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                    
                    if len(lines) > self.last_line_index:
                        new_lines = lines[self.last_line_index:]
                        
                        for line in new_lines:
                            try:
                                data = json.loads(line.strip())
                                time_str = data.get("timestamp", "").split("T")[-1][:8]
                                event_type = data.get("event_type", "Unknown")
                                
                                if event_type == "ProcessCreate":
                                    row_data = (
                                        time_str,
                                        data.get("process_name", ""),
                                        data.get("pid", ""),
                                        data.get("ppid", ""),
                                        data.get("file_path", ""),
                                        data.get("sha256", "HASH_UNAVAILABLE")[:16] + "...", 
                                        data.get("command_line", "")
                                    )
                                    tag = self.evaluate_threat_level(data.get("process_name", ""), data.get("file_path", ""))
                                
                                elif event_type == "NetworkConnection":
                                    # Map network data logically into the existing Process columns
                                    row_data = (
                                        time_str,
                                        f"[{data.get('status')}] {data.get('protocol')}", 
                                        data.get("pid", ""),
                                        "N/A",
                                        data.get("remote_address", ""),                   
                                        "N/A",
                                        f"Local: {data.get('local_address', '')}"         
                                    )
                                    tag = "network_blue"
                                    
                                elif event_type == "FileEvent":
                                    # Map FIM data logically into the existing columns
                                    row_data = (
                                        time_str,
                                        f"FIM: {data.get('action')}", 
                                        "N/A",
                                        "N/A",
                                        data.get("file_path", ""),                   
                                        "N/A",
                                        "Target: C:\\Users\\Public"         
                                    )
                                    tag = "file_purple"
                                    
                                elif event_type == "RegistryEvent":
                                    row_data = (
                                        time_str,
                                        f"RIM: {data.get('action')}", 
                                        "N/A",
                                        "N/A",
                                        f"{data.get('key_path')} -> {data.get('value_name')}",
                                        "N/A",
                                        f"Payload: {data.get('payload')}"         
                                    )
                                    tag = "registry_orange"
                                else:
                                    continue
                                
                                self.tree.insert("", tk.END, values=row_data, tags=(tag,))
                            except json.JSONDecodeError:
                                pass
                                
                        self.tree.yview_moveto(1)
                        self.last_line_index = len(lines)
            except PermissionError:
                pass

        self.root.after(2000, self.refresh_logs)

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("Treeview", background="#1e1e1e", foreground="#d4d4d4", fieldbackground="#1e1e1e", rowheight=25)
    style.map('Treeview', background=[('selected', '#005599')])
    style.configure("Treeview.Heading", background="#333333", foreground="white", font=('Consolas', 10, 'bold'))
    
    app = EDRDashboard(root)
    root.mainloop()
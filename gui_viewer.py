import tkinter as tk
from tkinter import scrolledtext
import os

# Define the exact same system path our daemon is writing to
PROGRAM_DATA_DIR = os.path.join(os.environ.get("PROGRAMDATA", "C:\\ProgramData"), "EDR_Agent")
# LOG_FILE = os.path.join(PROGRAM_DATA_DIR, "agent_heartbeat.log")
LOG_FILE = os.path.join(PROGRAM_DATA_DIR, "agent_telemetry.log")

class EDRAgentGUI:
    def __init__(self, root):
        """
        WHAT: Initializes the Graphical User Interface.
        """
        self.root = root
        self.root.title("EDR Agent - Live Logs")
        self.root.geometry("700x450")
        
        # Make it look like a security terminal
        self.root.configure(bg="#0c0c0c")
        
        # Create a scrolling text box
        self.text_area = scrolledtext.ScrolledText(
            self.root, wrap=tk.WORD, bg="#0c0c0c", fg="#00ff00", 
            font=("Consolas", 10), state=tk.DISABLED
        )
        self.text_area.pack(padx=10, pady=10, expand=True, fill='both')

        # Start the automatic refresh loop
        self.refresh_logs()

    def refresh_logs(self):
        """
        WHAT: Safely reads the log file and updates the screen.
        WHEN: Called immediately, then schedules itself to run every 2000ms (2 seconds).
        WHY: To provide a 'live' view without blocking the main UI thread.
        """
        if os.path.exists(LOG_FILE):
            try:
                # HOW: We open in 'r' (read) mode. Windows allows concurrent reading 
                # while our Session 0 daemon is writing.
                with open(LOG_FILE, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Temporarily enable the text box to insert new text
                self.text_area.config(state=tk.NORMAL)
                self.text_area.delete(1.0, tk.END)
                self.text_area.insert(tk.END, content)
                
                # Auto-scroll to the absolute bottom to see the newest logs
                self.text_area.see(tk.END)
                
                # Disable the text box so the user can't type in it
                self.text_area.config(state=tk.DISABLED)
                
            except PermissionError:
                # Edge Case: If we hit the exact millisecond the daemon is flushing to disk,
                # we just ignore it and wait for the next 2-second cycle.
                pass

        # Ask tkinter to call this exact function again in 2000 milliseconds
        self.root.after(2000, self.refresh_logs)

if __name__ == "__main__":
    root = tk.Tk()
    app = EDRAgentGUI(root)
    root.mainloop()
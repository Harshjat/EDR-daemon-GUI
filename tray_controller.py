import pystray
from pystray import MenuItem as item
from PIL import Image, ImageDraw
import subprocess
import os
import sys

# Ensure we know exactly where the GUI script is located
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
GUI_SCRIPT = os.path.join(CURRENT_DIR, "gui_viewer.py")

def create_icon_image():
    """
    Creates a visual representation for the system tray (a blue shield/square).
    """
    image = Image.new('RGB', (64, 64), color=(0, 0, 0))
    draw = ImageDraw.Draw(image)
    # Draw a blue square to differentiate it from our old red test
    draw.rectangle((16, 16, 48, 48), fill=(0, 100, 255)) 
    return image

def open_gui(icon, item):
    """
    WHAT: Triggers when 'Open Dashboard' is clicked.
    HOW: Uses subprocess.Popen to launch the GUI completely decoupled from the Tray.
    WHY: If the GUI freezes, the Tray icon is entirely unaffected.
    """
    if os.path.exists(GUI_SCRIPT):
        # We use pythonw.exe so the GUI launches without a background console window
        subprocess.Popen([sys.executable.replace("python.exe", "pythonw.exe"), GUI_SCRIPT])
    else:
        print(f"[!] Cannot find {GUI_SCRIPT}")

def quit_tray(icon, item):
    """
    WHAT: Stops the system tray icon.
    NOTE: This DOES NOT stop the Session 0 EDR Daemon. That requires Admin privileges.
    """
    icon.stop()

def main():
    print("Starting User-Mode Tray Controller...")
    
    menu = pystray.Menu(
        item('Open Dashboard', open_gui, default=True), # default=True means double-click opens it
        pystray.Menu.SEPARATOR,
        item('Exit Tray (Leaves Agent Running)', quit_tray)
    )
    
    tray_icon = pystray.Icon("EDR_Tray", create_icon_image(), "EDR Agent (Protected)", menu)
    tray_icon.run()

if __name__ == "__main__":
    main()
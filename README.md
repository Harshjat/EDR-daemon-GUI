# Windows EDR Agent Prototype

A foundational Endpoint Detection and Response (EDR) agent prototype demonstrating Windows process isolation, Session 0 / Session 1 separation, and safe IPC via file I/O.

## Architecture Overview

Modern Windows security dictates that background services cannot interact directly with the user desktop. This project follows enterprise architecture by splitting the application into distinct components.

### Kernel Bridge (Session 0)

- `daemon_core.py`: Worker thread that writes heartbeat telemetry to disk.
- `service_wrapper.py`: Windows Service wrapper that runs as `NT AUTHORITY\SYSTEM`, auto-starts on boot, and survives user logouts.

### User Mode Interface (Session 1)

- `tray_controller.py`: Lightweight system tray controller launched at user login via HKCU Run key.
- `gui_viewer.py`: Decoupled Tkinter dashboard that reads log telemetry from `C:\ProgramData\EDR_Agent`.

## IPC (Inter-Process Communication)

- The daemon writes heartbeat logs to `C:\ProgramData\EDR_Agent\agent_heartbeat.log`.
- The user-mode GUI reads this file asynchronously and handles `PermissionError` when the daemon is writing.

## Prerequisites

- Python 3.x installed and available in `PATH`.
- Required Python packages:

```powershell
pip install pystray pillow pywin32
```

> On Windows, use `python` or `python3` depending on your environment.

## Installation

1. Download or clone this repository.
2. Ensure all required files are in the same folder:
   - `daemon_core.py`
   - `service_wrapper.py`
   - `gui_viewer.py`
   - `tray_controller.py`
   - `installer.py`
3. Run the installer as Administrator:

```powershell
python installer.py
```

The installer will:

- create `C:\Program Files\EDR_Agent` and `C:\ProgramData\EDR_Agent`
- copy core scripts into Program Files
- register and start the Windows service
- create an HKCU Run key for the tray icon
- launch the tray UI

## Uninstallation

Run the uninstaller as Administrator from the repository folder:

```powershell
python uninstaller.py
```

This will:

- stop the tray and GUI processes
- stop and delete the Windows service
- remove the HKCU Run registry key
- delete the installed Program Files and ProgramData directories

## Disclaimer

This project is an educational prototype intended to demonstrate Windows service architecture and safe process separation. It is not a production-ready EDR solution.

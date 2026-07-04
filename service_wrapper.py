import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import os
import sys
import threading

# Ensure the directory of the service is in the Python path 
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import daemon_core

class EDRAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "EDRAgentService"
    _svc_display_name_ = "EDR Agent Background Service"
    _svc_description_ = "Monitors system events and writes heartbeat logs. Runs in Session 0."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.stop_event = threading.Event()

    def SvcStop(self):
        """Triggered by the OS when shutting down."""
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        self.stop_event.set()

    def SvcDoRun(self):
        """Triggered by the OS when the service starts."""
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.main()

    def main(self):
        """Executes the actual workload."""
        # Start all sensor loops in background threads
        sensor_threads = daemon_core.start_sensors(self.stop_event)
        
        # Block indefinitely until SCM tells us to stop
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
        
        # Wait for all worker threads to finish writing cleanly
        for t in sensor_threads:
            t.join()

if __name__ == '__main__':
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(EDRAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(EDRAgentService)
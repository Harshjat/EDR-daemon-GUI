import win32serviceutil
import win32service
import win32event
import servicemanager
import socket
import os
import sys
import threading

# THE FIX: Ensure the directory of the service is in the Python path 
# so we can successfully import daemon_core when running from System32.
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import daemon_core

class EDRAgentService(win32serviceutil.ServiceFramework):
    # Standard internal name (no spaces)
    _svc_name_ = "EDRAgentService"
    # What the admin actually sees in services.msc
    _svc_display_name_ = "EDR Agent Background Service"
    _svc_description_ = "Monitors system events and writes heartbeat logs. Runs in Session 0."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        # Create a Windows Event object. This is how the OS signals us to stop.
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        # Create our Python Threading Event to pass into your daemon_core
        self.stop_event = threading.Event()

    def SvcStop(self):
        """
        WHAT: Triggered by the OS when the system is shutting down, 
        or when an Admin stops the service manually.
        """
        # 1. Tell SCM "I received the command, I am shutting down now."
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        
        # 2. Fire the Win32 Event to break the SvcDoRun waiting state
        win32event.SetEvent(self.hWaitStop)
        
        # 3. Signal our background Python loop to finish its current log write and exit.
        self.stop_event.set()

    def SvcDoRun(self):
        """
        WHAT: Triggered by the OS when the service starts.
        """
        # Tell SCM we have successfully started. If we don't do this, Windows kills us.
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        self.main()

    def main(self):
        """
        Executes the actual workload.
        """
        # We start your daemon loop in a background thread.
        worker_thread = threading.Thread(target=daemon_core.agent_worker_loop, args=(self.stop_event,))
        worker_thread.start()
        
        # SvcDoRun must not exit until the service is stopped.
        # This line forces the main thread to sleep indefinitely until SvcStop fires hWaitStop.
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
        
        # Once hWaitStop is fired, wait for the worker thread to finish writing cleanly.
        worker_thread.join()

if __name__ == '__main__':
    # Standard pywin32 boilerplate to handle command line arguments (install/start/stop)
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(EDRAgentService)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(EDRAgentService)
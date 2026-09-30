"""Hidden-window SetupAPI device-interface notifications (Windows only)."""
from __future__ import annotations

import ctypes
import queue
import threading
import time
from ctypes import wintypes

GUIDS = {
    # GUID_DEVINTERFACE_COMPORT (not the Ports setup-class GUID)
    "ports": "86E0D1E0-8089-11D0-9CE4-08003E301F73",
    "usb": "A5DCBF10-6530-11D2-901F-00C04FB951ED",
}


class GUID(ctypes.Structure):
    _fields_ = [("Data1", wintypes.DWORD), ("Data2", wintypes.WORD), ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8)]


def parse_guid(value: str) -> GUID:
    import uuid
    u = uuid.UUID(value)
    b = u.bytes_le
    return GUID.from_buffer_copy(b)


class DeviceInterfaceFilter(ctypes.Structure):
    _fields_ = [("dbcc_size", wintypes.DWORD), ("dbcc_devicetype", wintypes.DWORD), ("dbcc_reserved", wintypes.DWORD), ("dbcc_classguid", GUID), ("dbcc_name", wintypes.WCHAR * 1)]


class DeviceEventWatcher:
    def __init__(self):
        self.events: queue.Queue = queue.Queue()
        self.error = None
        self._thread = threading.Thread(target=self._run, name="pnp-notifications", daemon=True)
        self._thread.start()

    def _run(self):
        if not hasattr(ctypes, "windll"):
            self.error = "Windows device notifications unavailable on this platform"
            return
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.DefWindowProcW.restype = ctypes.c_ssize_t
        user32.RegisterDeviceNotificationW.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
        user32.RegisterDeviceNotificationW.restype = wintypes.HANDLE
        user32.UnregisterDeviceNotification.argtypes = [wintypes.HANDLE]
        user32.UnregisterDeviceNotification.restype = wintypes.BOOL
        user32.GetMessageW.argtypes = [ctypes.POINTER(wintypes.MSG), wintypes.HWND, wintypes.UINT, wintypes.UINT]
        user32.GetMessageW.restype = ctypes.c_int
        WM_DEVICECHANGE = 0x0219
        DBT_DEVICEARRIVAL = 0x8000
        DBT_DEVICEREMOVECOMPLETE = 0x8004
        DBT_DEVTYP_DEVICEINTERFACE = 0x00000005
        DEVICE_NOTIFY_WINDOW_HANDLE = 0x00000000
        HWND_MESSAGE = wintypes.HWND(-3)
        WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM)
        watcher = self

        @WNDPROC
        def wndproc(hwnd, msg, wparam, lparam):
            if msg == WM_DEVICECHANGE and wparam in (DBT_DEVICEARRIVAL, DBT_DEVICEREMOVECOMPLETE) and lparam:
                try:
                    header = ctypes.cast(lparam, ctypes.POINTER(wintypes.DWORD * 2)).contents
                    if header[1] == DBT_DEVTYP_DEVICEINTERFACE:
                        path_offset = DeviceInterfaceFilter.dbcc_name.offset
                        path = ctypes.wstring_at(lparam + path_offset)
                        watcher.events.put({
                            "event": "ADDED" if wparam == DBT_DEVICEARRIVAL else "REMOVED",
                            "path": path,
                            "monotonic_ns": time.perf_counter_ns(),
                            "pnp_monotonic_ns": time.perf_counter_ns(),
                        })
                except Exception as exc:
                    watcher.events.put({"event": "ERROR", "error": repr(exc), "monotonic_ns": time.perf_counter_ns()})
            return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

        class WNDCLASS(ctypes.Structure):
            _fields_ = [("style", wintypes.UINT), ("lpfnWndProc", WNDPROC), ("cbClsExtra", ctypes.c_int), ("cbWndExtra", ctypes.c_int), ("hInstance", wintypes.HINSTANCE), ("hIcon", wintypes.HICON), ("hCursor", wintypes.HANDLE), ("hbrBackground", wintypes.HANDLE), ("lpszMenuName", wintypes.LPCWSTR), ("lpszClassName", wintypes.LPCWSTR)]

        class_name = f"F2TransientWatcher_{id(self):x}"
        wc = WNDCLASS(0, wndproc, 0, 0, kernel32.GetModuleHandleW(None), None, None, None, None, class_name)
        atom = user32.RegisterClassW(ctypes.byref(wc))
        if not atom:
            self.error = f"RegisterClassW failed: {ctypes.get_last_error()}"
            return
        hwnd = user32.CreateWindowExW(0, class_name, class_name, 0, 0, 0, 0, 0, HWND_MESSAGE, None, wc.hInstance, None)
        if not hwnd:
            self.error = f"CreateWindowExW failed: {ctypes.get_last_error()}"
            return
        registrations = []
        try:
            for class_guid in GUIDS.values():
                filt = DeviceInterfaceFilter(ctypes.sizeof(DeviceInterfaceFilter), DBT_DEVTYP_DEVICEINTERFACE, 0, parse_guid(class_guid), "")
                handle = user32.RegisterDeviceNotificationW(hwnd, ctypes.byref(filt), DEVICE_NOTIFY_WINDOW_HANDLE)
                if handle:
                    registrations.append(handle)
                else:
                    self.events.put({"event": "ERROR", "error": f"RegisterDeviceNotificationW failed: {ctypes.get_last_error()}", "monotonic_ns": time.perf_counter_ns()})
            msg = wintypes.MSG()
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                user32.TranslateMessage(ctypes.byref(msg))
                user32.DispatchMessageW(ctypes.byref(msg))
        finally:
            for handle in registrations:
                user32.UnregisterDeviceNotification(handle)
            user32.DestroyWindow(hwnd)
            user32.UnregisterClassW(class_name, wc.hInstance)

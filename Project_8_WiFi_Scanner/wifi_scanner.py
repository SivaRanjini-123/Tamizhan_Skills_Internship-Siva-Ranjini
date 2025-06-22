import pywifi
from pywifi import const
import time
import os

def scan_wifi_networks():
    """
    Scans for available Wi-Fi networks and prints their information.
    """
    wifi = pywifi.PyWiFi()
    iface = None

    # Try to find an active Wi-Fi interface
    # Iterate through available interfaces and pick one that is connected or disconnected
    # (i.e., not a virtual/loopback interface)
    for iface_obj in wifi.interfaces():
        if iface_obj.status() == const.IFACE_CONNECTED or iface_obj.status() == const.IFACE_DISCONNECTED:
            iface = iface_obj
            break

    if iface is None:
        print("No active Wi-Fi interface found. Please ensure your Wi-Fi adapter is enabled.")
        print("On Windows, try running this script as Administrator.")
        return

    print(f"Using Wi-Fi interface: {iface.name()}")
    print("-" * 40)
    print("Scanning for Wi-Fi networks...")

    # Initiate scan
    iface.scan()
    time.sleep(5)  # Give time for the scan to complete

    # Get scan results
    bsses = iface.scan_results()

    if not bsses:
        print("No Wi-Fi networks found.")
        print("Consider moving to a different location or checking your adapter status.")
        return

    print("\nFound Wi-Fi Networks:")
    print(f"{'SSID':<30} {'BSSID':<20} {'Signal (dBm)':<15} {'Channel':<10} {'Auth':<15}")
    print("-" * 90)

    for data in bsses:
        ssid = data.ssid if data.ssid else "[Hidden SSID]"
        bssid = data.bssid.upper() if data.bssid else "N/A"
        signal = data.signal
        
        # Handle potential missing 'channel' attribute
        channel = data.channel if hasattr(data, 'channel') else "N/A" 
        
        auth = ""
        if data.auth:
            for auth_type in data.auth:
                if auth_type == const.AUTH_ALG_OPEN:
                    auth += "Open "
                elif auth_type == const.AUTH_ALG_WEP:
                    auth += "WEP "
                elif auth_type == const.AUTH_ALG_WPA:
                    auth += "WPA "
                elif auth_type == const.AUTH_ALG_WPA2:
                    auth += "WPA2 "
                elif auth_type == const.AUTH_ALG_FT: # Fast Transition (WPA3-like)
                    auth += "FT "
                elif auth_type == const.AUTH_ALG_SAE: # WPA3-SAE
                    auth += "WPA3 "
                # Add more authentication types as needed from pywifi.const if you encounter them
            auth = auth.strip() if auth else "Unknown" # Clean up trailing space if multiple auths, or set to Unknown

        print(f"{ssid:<30} {bssid:<20} {signal:<15} {channel:<10} {auth:<15}")

    print("-" * 90)

if __name__ == "__main__":
    # Check for administrator privileges on Windows and provide warning
    if os.name == 'nt': # If OS is Windows
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("Warning: On Windows, you may need to run this script as an administrator for Wi-Fi scanning to work correctly.")
                print("Please right-click on your Anaconda Prompt shortcut and choose 'Run as administrator'.")
        except Exception as e:
            print(f"Could not check admin status: {e}")
    
    scan_wifi_networks()
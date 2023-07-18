import os
import time
import subprocess

class WiFiManager:
    def __init__(self, interface="wlan0"):
        self.retry_interval = 5 # seconds
        self.interface = interface

    def scan_wifi_networks(self, retries=1):
        wifi_list = []
        for i in range(retries):
            try:
                proc = subprocess.Popen(["sudo", "iwlist", self.interface, "scan"], stdout=subprocess.PIPE, universal_newlines=True)
                for line in proc.stdout:
                    if "ESSID" in line:
                        ssid = line.strip().split(":")[1].replace('"', '')
                        wifi_list.append(ssid)
                break
            except Exception as e:
                print(f"Error scanning for Wi-Fi networks: {e}")
                if i < retries - 1:
                    print(f"Retrying in {self.retry_interval} seconds...")
                    time.sleep(self.retry_interval)
                else:
                    return None
        return wifi_list

    def find_wifi_network(self, target_substring, retries=1):
        print(f"Searching for Target Wifi network: '{target_substring}'!")
        for _ in range(retries):
            wifi_list = self.scan_wifi_networks()
            if wifi_list is None:
                continue
            for wifi in wifi_list:
                if target_substring in wifi:
                    print(f"Found Target Wifi network: '{wifi}'!")
                    return wifi
            time.sleep(self.retry_interval)
        return None

    def is_connected(self, ssid):
        proc = subprocess.Popen(["iwgetid", "-r"], stdout=subprocess.PIPE, universal_newlines=True)
        stdout, _ = proc.communicate()
        if ssid in stdout.strip():
            print(f"Connected to Wi-Fi network: {ssid}")
            return True
        else:
            return False

    def connect_to_wifi(self, ssid, password, retries=1):
        for i in range(retries):
            try:
                command = f"sudo nmcli dev wifi connect \"{ssid}\" password \"{password}\""
                #print(f"DEBUG: Sending Command: '{command}'")
                os.system(command)
                #proc = subprocess.run(command, shell=True, executable='/bin/bash')
                time.sleep(2)
                if self.is_connected(ssid):
                    return True
            except Exception as e:
                print(f"Error connecting to Wi-Fi network: {e}")
                if i < retries - 1:
                    print(f"Retrying in {self.retry_interval} seconds...")
                    time.sleep(self.retry_interval)
                else:
                    return False
        return False
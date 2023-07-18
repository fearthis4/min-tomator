from bluepy.btle import Scanner, DefaultDelegate, Peripheral, UUID

class BLEDevice:
    def __init__(self, target_device_name, target_mac_address=None):
        self.target_device_name = target_device_name
        self.target_mac_address = target_mac_address 
        self.device = None

    def scan(self, timeout=5, retries=1):
        print(f"Scanning for target BLE Device: '{self.target_device_name}'")
        scanner = Scanner()
        for _ in range(retries):
            devices = scanner.scan(timeout)
            for dev in devices:
                #print(f"Discovered BLE Device: '{dev.addr}' - '{dev.getValueText(9)}'")
                if dev.getValueText(9) == self.target_device_name and (self.target_mac_address is None or dev.addr == self.target_mac_address):
                    print(f"Found target BLE device: {self.target_device_name}")
                    return dev.addr
        print(f"Target BLE device {self.target_device_name} not found after {retries} retries")
        return None

    def connect(self, device_address, retries=1):
        print(f"Connecting to BLE Device: '{self.target_device_name}'...")
        if device_address is None:
            return False
        for _ in range(retries):
            try:
                self.device = Peripheral(device_address)
                return True
            except Exception as e:
                print(f"Error connecting to BLE device {self.target_device_name}: {e}")
            print("Retrying...")
        if self.device is None:
            return False 

    def send_data(self, service_uuid, char_uuid, value):
        print("Sending data to BLE Device.")
        if self.device is None:
            return False
        try:
            service = self.device.getServiceByUUID(service_uuid)
            characteristic = service.getCharacteristics(char_uuid)[0]
            characteristic.write(value)
            return True
        except Exception as e:
            print(f"Error sending data to device {self.target_device_name}: {e}")
            return False
    
    def disconnect(self):
        if self.device is None:
            print(f"No BLE device connected")
            return False
        try:
            self.device.disconnect()
            print(f"Disconnected from BLE device: {self.target_device_name}")
            self.device = None
            return True
        except Exception as e:
            print(f"Error disconnecting from BLE device {self.target_device_name}: {e}")
            return False
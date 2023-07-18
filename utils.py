import os
import yaml
import json
import fcntl
import struct
import shutil
import socket
import urllib3
import requests
import subprocess
from pathlib import Path
import paho.mqtt.publish as MQTTPublish

# provides functions / classes needed to interact with DSOON Wifi/BLE Trail Cams

class BindToDeviceHTTPAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.interface = kwargs.pop('interface', None)
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        self.poolmanager = urllib3.PoolManager(*args, **kwargs,
                                                socket_options=self._get_socket_options())

    def _get_socket_options(self):
        if self.interface is not None:
            return [(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface.encode())]
        else:
            return []


def get_interface_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        ip_address = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(),
            0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname[:15].encode())
        )[20:24])
    except IOError:
        ip_address = None
    finally:
        s.close()
    return ip_address

def yaml_include(loader, node):
    # Get the included file path
    included_file = os.path.abspath(os.path.join(os.path.dirname(loader.name), node.value))
    # Load the included file
    with open(included_file, 'r') as file:
        return yaml.load(file, Loader=loader.__class__)

# Add the include tag handler to the YAML loader
yaml.SafeLoader.add_constructor('!include', yaml_include)

def load_config(config_file_path):
    with open(config_file_path, "r") as f:
        config = yaml.safe_load(f)
    return config

def config_exists(config_key, config):
    if config_key in config.keys():
        return True
    else:
        return False
    
def roll_config(tmp_file_path, target_file_path):
    # Check if the target file already exists
    if os.path.exists(target_file_path):
        # Backup the existing target file
        backup_file_path = target_file_path + '.bak'
        shutil.copy2(target_file_path, backup_file_path)

    # Move the new tmp file to the target path
    shutil.move(tmp_file_path, target_file_path)

def find_new_files(file_path, file_dict):
    new_files = []
    with open(file_path, 'r') as f:
        try:
            existing_files = set(json.load(f))
        except json.JSONDecodeError:
            existing_files = set()
    for filename, contents in file_dict.items():
        if filename not in existing_files:
            new_files.append(filename)
    return new_files

def load_json_file_list(file_path):
    try:
        with open(file_path) as f:
            data = json.load(f)
            return data
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading JSON file: {e}")
        return None

def longest_list(list1, list2):
    if len(list1) > len(list2):
        return list1
    else:
        return list2

def delete_file(file_path):
    try:
        os.remove(file_path)
        print(f"File {file_path} deleted successfully.")
    except OSError as e:
        print(f"Error deleting file {file_path}: {e}")

def convert_video(input_file, output_file):
    input_extension = os.path.splitext(input_file)[1].lower()
    output_extension = os.path.splitext(output_file)[1].lower()
    if output_extension not in ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm']:
        raise ValueError(f"Unsupported output format: {output_extension}")
    if input_extension not in ['.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm']:
        raise ValueError(f"Unsupported input format: {input_extension}")
    # Set up FFmpeg command
    ffmpeg_command = [
        'ffmpeg',
        '-i', input_file,
        '-strict', '-2',
        output_file
    ]
    # Run FFmpeg command
    subprocess.run(ffmpeg_command, check=True)

def convert_all_videos(dir, format):
    try:
        # Check if format is supported
        if format not in ['mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm']:
            raise ValueError(f"Unsupported output format: {format}")
        # Iterate over files in input directory
        for filename in os.listdir(dir):
            # Check if file is a video file
            if not filename.lower().endswith(('.avi', '.mp4', '.mov', '.wmv', '.flv', '.mkv', '.webm')):
                continue
            # Create input and output paths
            input_path = os.path.join(dir, filename)
            output_path = os.path.join(dir, os.path.splitext(filename)[0] + '.' + format)
            # Skip file if it's already in the target format
            if os.path.exists(output_path):
                continue
            try:
                # Convert video
                convert_video(input_path, output_path)
            except subprocess.CalledProcessError as e:
                # Handle FFmpeg errors
                print(f"Error converting {filename}: {e.stderr}")
                continue
            try:
                # Remove old video file
                os.remove(input_path)
            except OSError as e:
                # Handle file removal errors
                print(f"Error removing {filename}: {e}")
                continue
    except ValueError as e:
        # Handle unsupported format errors
        print(e)

def get_file_type(file_path):
    # determine the file type based on the file extension
    file_extension = file_path.split(".")[-1].lower()
    if file_extension in ("jpg", "jpeg", "png", "gif"):
        return "image"
    elif file_extension in ('mp4', 'avi', 'mov', 'wmv', 'flv', 'mkv', 'webm'):
        return "video"
    else:
        print(f"Unsupported file type: {file_extension}")
        return None

def format_mqtt_topic(topic, prefix, full_topic_template):
    # Replace %topic% with topic
    full_topic = full_topic_template.replace('%topic%', topic)
    # Replace %prefix% with prefix
    full_topic = full_topic.replace('%prefix%', prefix)
    return full_topic

def send_file_data_to_telegram(token, chat_id, file_name, file_data, file_type):
    # Set type for api call
    if file_type in ("image", "photo"):
        api_type = "Photo"
    elif file_type in ("video"):
        api_type = "Video"
    else:
        print(f"Unsupported file type: {file_type}")
        return False
        
    # Make the API request to send the file
    url = f"https://api.telegram.org/bot{token}/send{api_type}"
    data = {"chat_id": chat_id}
    files = {api_type.lower(): (file_name, file_data)}
    response = requests.post(url, data=data, files=files)
    if not response.ok:
        print(f"Failed to send {file_type}: '{response.text}'!")
        return False
    else:
        print(f"{file_type} sent successfully!")
        return True
    
def recursive_dict_update(original_dict, new_dict):
    for key, value in new_dict.items():
        if isinstance(value, dict) and key in original_dict and isinstance(original_dict[key], dict):
            original_dict[key] = recursive_dict_update(original_dict[key], value)
        else:
            original_dict[key] = value
    return original_dict

def make_archive(source, destination):
    src = Path(source)
    dst = Path(destination)
    base_name = dst.parent / dst.stem
    fmt = dst.suffix.replace(".", "")
    root_dir = src.parent
    base_dir = src.name
    shutil.make_archive(str(base_name), fmt, root_dir, base_dir)
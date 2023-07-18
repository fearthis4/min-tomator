#!/usr/bin/python3
import os
import re
import time
import yaml
import shlex
import subprocess
import datetime
import argparse
import http.server
import socketserver
import signal
import select
from functools import partial
from threading import Thread, Lock

NAME="Min-Tomator Core"
VERSION="v0.1"
STARTUP_INFO="Minimal Automation Framework By Chris Jones"
# Global lock for script execution
script_lock = Lock()
# Globals
config_file = "config.yml"
port_handler_active = False
web_interface_process = None
web_interface_active = False
last_activity_time = time.time()

class PortHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.protocol = kwargs.pop('protocol', 'http')
        super().__init__(*args, **kwargs)

    def do_GET(self):
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            # HTML content for the initial page
            html_content = f'''
            <html>
            <head>
                <title>Initializing Web Interface...</title>
                <meta http-equiv="refresh" content="6;URL='{protocol}://{self.headers['Host']}/'" />
            </head>
            <body>
                <h1>Initializing Web Interface....</h1>
            </body>
            </html>
            '''
            self.wfile.write(html_content.encode())

def start_port_handler(host, port, protocol):
    global port_handler_active
    if not port_handler_active:
        port_handler_active = True
        print(f'Starting Port handler on: {host}:{port} with protocol: {protocol}')
        # Set TCP to non-blocking
        socketserver.TCPServer.allow_reuse_address = True
        # Initialize port handler server
        #server = socketserver.TCPServer((host, port), PortHandler)
        handler = partial(PortHandler, protocol=protocol)
        server = socketserver.TCPServer((host, port), handler)
        try:
            # Handle single request
            server.handle_request()
            print(f'Port handler recieved a request on: {host}:{port}')
        except:
            pass
        # Stop port handler after request is served
        print('Stopping Port handler')
        time.sleep(4)
        port_handler_active = False

def stop_port_handler(host, port):
    global port_handler_active
    if port_handler_active:
        port_handler_active = False
        # Create a temporary client to connect to the server and shut it down gracefully
        try:
            client = socketserver.TCPServer((host, port), http.server.SimpleHTTPRequestHandler)
            client.shutdown()
            print('Port handler stopped')
        except ConnectionRefusedError:
            pass

def stop_external_processes():
    global web_interface_active
    if web_interface_active:
        stop_web_interface()

def signal_handler(signum, frame):
    # Signal handler function to handle Ctrl+C or SIGTERM signal
    print("Signal received. Stopping all processes...")
    stop_external_processes()
    os._exit(0)  # Exit the program immediately

def setup_signal_handler():
    # Set up the signal handler for Ctrl+C or SIGTERM
    signal.signal(signal.SIGINT, signal_handler)   # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # SIGTERM
    print("Signal handler set up. Press Ctrl+C to stop.")

def start_web_interface(config):
    global web_interface_process
    global web_interface_active

    script_path = config.get('config_web_interface', {}).get('script', "./config_web_interface.py -s 'config_web_interface'")

    print(f"Starting web interface app: {script_path}")
    args = shlex.split(script_path)
    #web_interface_process = subprocess.Popen(args, preexec_fn=os.setsid)
    web_interface_process = subprocess.Popen(args, preexec_fn=os.setsid, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    web_interface_active = True

    # Start a separate thread to monitor the output
    monitor_thread = Thread(target=monitor_web_interface, args=(web_interface_process,))
    monitor_thread.start()

def stop_web_interface():
    global web_interface_process
    global web_interface_active

    # Stop the web interface if it's active
    if web_interface_active:
        os.killpg(os.getpgid(web_interface_process.pid), signal.SIGTERM)
        print("Web interface stopped.")
        web_interface_process = None
        web_interface_active = False

def monitor_web_interface(process):
    timeout = 10 * 60  # 10 minutes timeout

    print(f"Starting Process watcher for web interface")

    while process.poll() is None:
        ready, _, _ = select.select([process.stdout], [], [], timeout)

        if ready:
            output = process.stdout.readline().decode().strip()
            if output:
                print(output)
        else:
            print("Web interface process has not seen any requests for 10 minutes. Stopping...")
            stop_web_interface()
            break

    # Wait for the process to finish
    process.wait()
    print("Web interface process has stopped.")

def run_script(script_path, log_file):
    # Acquire the script lock
    with script_lock:
        try:
            # Redirect the script output to the log file
            with open(log_file, 'a') as file:
                subprocess.run(script_path, shell=True, check=True, stdout=file, stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print(f"Error running script: {script_path}")
            print(e)

def schedule_scripts(config):
    logging_config = config.get('logging', {})
    log_file = logging_config.get('file')

    while True:
        # Iterate over the extra_scripts in the config
        for script_name, script_data in config.get('extra_scripts', {}).items():
            script_path = script_data.get('script')
            run_frequency = script_data.get('run_frequency')

            # Run the script if it's time and the lock is available
            if script_path and run_frequency:
                next_run_time = script_data.get('next_run_time', 0)
                current_time = time.time()

                if current_time >= next_run_time:
                    # Update the next run time
                    run_interval = parse_run_frequency(run_frequency)
                    script_data['next_run_time'] = current_time + run_interval

                    # Start a thread to run the script
                    script_thread = Thread(target=run_script, args=(script_path, log_file))
                    script_thread.start()

        # Wait for a while before checking the scripts again
        time.sleep(1)

def parse_run_frequency(run_frequency):
    # Parse the run frequency string to determine the run interval
    if run_frequency.endswith('s'):
        return int(run_frequency[:-1])
    elif run_frequency.endswith('m'):
        return int(run_frequency[:-1]) * 60
    elif run_frequency.endswith('h'):
        return int(run_frequency[:-1]) * 60 * 60
    elif run_frequency.endswith('d'):
        return int(run_frequency[:-1]) * 60 * 60 * 24
    else:
        return 0

def watch_config_file(config_file):
    last_modified_time = os.path.getmtime(config_file)

    while True:
        modified_time = os.path.getmtime(config_file)

        if modified_time > last_modified_time:
            try:
                with open(config_file, 'r') as file:
                    config = yaml.safe_load(file)
                    schedule_scripts(config)
            except Exception as e:
                print(f"Error reading config file: {config_file}")
                print(e)

            last_modified_time = modified_time

        time.sleep(1)

def watch_port_traffic(host, port, protocol, config):
    global port_handler_active
    global web_interface_active
    global last_activity_time

    while True:
        try:
            # If web interface is not active and port handler is not active
            if not web_interface_active and not port_handler_active:
                # Start port handler and wait for a connection (blocking)
                start_port_handler(host, port, protocol)

            if not web_interface_active:
                start_web_interface(config)
        except OSError:
            pass

        time.sleep(1)

def parse_size_string(size_string):
    size_string = size_string.lower()
    match = re.match(r"^(\d+)([kmgtp]?)b?$", size_string)
    
    if not match:
        raise ValueError("Invalid size string")
    
    size = int(match.group(1))
    unit = match.group(2)
    
    if unit == 'k':
        size *= 1024
    elif unit == 'm':
        size *= 1024 * 1024
    elif unit == 'g':
        size *= 1024 * 1024 * 1024
    elif unit == 't':
        size *= 1024 * 1024 * 1024 * 1024
    elif unit == 'p':
        size *= 1024 * 1024 * 1024 * 1024 * 102
    return size

def rotate_log_on_size(log_file_path, max_size_string):
    # Check the size of the log file
    log_file_size = os.path.getsize(log_file_path)
    max_size_bytes = parse_size_string(max_size_string)
    
    if log_file_size > max_size_bytes:
        rotate_log_file(log_file_path)

def rotate_log_file(log_file_path):
    rotated_log_file = f"{log_file_path}.bkup"
    rotated_backup_file = f"{rotated_log_file}_1"

    # Backup last rotated file if it exists
    if os.path.exists(rotated_log_file):
          os.rename(rotated_log_file, rotated_backup_file)
    # Rename the current log file to the rotated log file if exists
    if os.path.exists(log_file_path):
        os.rename(log_file_path, rotated_log_file)
    
    # Create a new empty log file
    with open(log_file_path, "w") as new_log_file:
        new_log_file.write(f"[{datetime.datetime.now()}] - LOG ROTATION Done \n{NAME} {VERSION} - {STARTUP_INFO}\n")

def log_rotation_thread(log_file_path, max_size_string, interval):
    while True:
        rotate_log_on_size(log_file_path, max_size_string)
        time.sleep(interval)

# Main execution
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='Target config file', default=config_file)
    args = parser.parse_args()

    config_file = args.config
    print(f"Starting config watcher for: {config_file}")
    # Watch the config file for changes in a separate thread
    config_watcher_thread = Thread(target=watch_config_file, args=(config_file,))
    config_watcher_thread.start()

    print(f"Reading in config: {config_file}")
    # Run the scheduler for the initial config
    try:
        with open(config_file, 'r') as file:
            config = yaml.safe_load(file)
            print(f"Scheduling scripts")
            # Start a separate thread for the schedule_scripts loop
            script_scheduler_thread = Thread(target=schedule_scripts, args=(config,))
            script_scheduler_thread.start()
    except Exception as e:
        print(f"Error reading config file: {config_file}")
        print(e)

    # Pull config data for logging
    log_file_path = config['logging']['file']
    log_rotate_size = config['logging']['rotate_size']
    # Rotate the initial log
    rotate_log_file(log_file_path)
    # Start a separate thread for managing log size / rotation
    log_rotate_thread = Thread(target=log_rotation_thread, args=(log_file_path, log_rotate_size, 60))
    log_rotate_thread.start()

    config_web_interface_enabled = config['config_web_interface']['enabled']
    if config_web_interface_enabled:
        web_interface_settings = config.get('config_web_interface', {})
        # Pull config data for server
        host = web_interface_settings['host']
        port = web_interface_settings['port']
        if web_interface_settings.get('https', False):
            print(f"HTTPS Enabled for web interface.")
            protocol = "https"
        else:
            protocol = "http"
        # Setup signal handler for any externally running processes
        setup_signal_handler()
        # Start the port watcher on a separate thread
        print(f"Starting http port watcher for: {host}:{port}")
        port_watcher_thread = Thread(target=watch_port_traffic, args=(host, port, protocol, config))
        port_watcher_thread.start()
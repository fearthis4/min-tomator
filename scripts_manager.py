
import os
import yaml
import html
import shlex
import psutil
import socket
import argparse
import zipfile
import datetime
from threading import Thread
from html import escape
from flask import Flask, render_template, request, flash, redirect, url_for, session, jsonify, send_file
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import BooleanField, PasswordField, SubmitField, StringField
from wtforms.validators import DataRequired
from werkzeug.utils import secure_filename
#from werkzeug.security import generate_password_hash, check_password_hash
from OpenSSL import SSL

from utils import *

SCRIPTS_PATH = "./extra_scripts"

def install_script(script_name, script_dir, config_path):
    # Read in new config
    # Get script name from config
    # Verify script is not already setup
    # Merge settings
    # Add extra_script settings for runner
    # Write new config
    # Move script_path to match script_name
    pass

def install_script_package(package_file):
    # Read in new config
    new_config = load_config(f'package_file')
    # Get script name from config
    pass

def install_script_git_repo(repo_link):
    # Download the Git repository package from the provided API link
    response = requests.get(repo_link)
    
    if response.status_code == 200:
        # Create a temporary directory to extract the package
        temp_dir = f"{SCRIPTS_PATH}/tmp"
        os.makedirs(temp_dir, exist_ok=True)
        
        # Save the downloaded package to a temporary file
        package_file = os.path.join(temp_dir, 'package.zip')
        with open(package_file, 'wb') as file:
            file.write(response.content)
        
        # Extract the package to the "extra_scripts/tmp" folder
        unpack_package_file(package_file, temp_dir)
        
        # Remove the temporary package file
        os.remove(package_file)

        # Get install information from package details
        install_script_package(package_file)

        # Remove the temporary directory
        os.rmdir(temp_dir)
        
        return "Fetched Git repository package successfully"
    else:
        return f"Error fetching Git repository package: {response.status_code}"
    
def install_script_archive(package_file):
    # Make tmp script dir
    temp_dir = f"{SCRIPTS_PATH}/tmp"
    os.makedirs(temp_dir, exist_ok=True)
    # Save the downloaded package to a temporary file
    package_file = os.path.join(temp_dir, 'package.zip')
    with open(package_file, 'wb') as file:
        file.write(response.content)
    install_script_package(package_file)
    
    pass

def unpack_package_file(package_file, dest_path):
    # Unpack the package file to the dest_path folder
    shutil.unpack_archive(package_file, dest_path)

def merge_config_with_app(config_file, new_config_file):
    # Read the new config file to merge
    new_config = load_config(new_config_file)
    # Read app config file to merge
    app_config = load_config(config_file)
    
    # Merge the new config with the app's config
    merged_config = recursive_dict_update(app_config, new_config)
    
    # Check for conflicts in the merged config
    conflicts = find_config_conflicts(app_config, new_config)
    
    if conflicts:
        # Handle conflicts
        return f"Config merge conflicts detected: {conflicts}"
    
    # Write the merged config to the config.yml file
    with open(config_file, 'w') as file:
        yaml.dump(merged_config, file)
    
    return "Config merged successfully"

def find_config_conflicts(original_dict, new_dict):
    conflicts = []
    for key, value in new_dict.items():
        if isinstance(value, dict) and key in original_dict and isinstance(original_dict[key], dict):
            sub_conflicts = find_config_conflicts(original_dict[key], value)
            conflicts.extend([f"{key}.{sub_key}" for sub_key in sub_conflicts])
        elif key in original_dict:
            conflicts.append(key)
    return conflicts

def list_script_names(config):
    script_names = []
    for script in config.get('extra_scripts', []):
        script_names.append(script)
    return script_names

def get_script_directory(script_name, config):
    # Search for the script name in the extra scripts section of config
    scripts_config = config.get('extra_scripts')
    if scripts_config:
        script_command = scripts_config[script_name].get('script')
        if script_command:
            script_directory = os.path.dirname(script_command.split(" ")[0])
            # Return the script directory path
            return script_directory
    # If the script name is not found in the config
    return None

def create_script_package(script_name, config, dest_file=None):
    # Destination file default if not set
    if dest_file == None:
        dest_file = f'{SCRIPTS_PATH}/tmp/{script_name}.zip'
    try:
        script_directory = get_script_directory(script_name, config)
        if script_directory:
            # Create directory to store the zip file
            os.makedirs(os.path.dirname(dest_file), exist_ok=True)
            # Create a zip file with the script directory and relevant config snippet
            make_archive(script_directory, dest_file)
            with zipfile.ZipFile(dest_file, 'a') as zip_file:
                config_snippet = get_config_snippet(script_name, config)
                zip_file.writestr('config.yml', config_snippet)
            return ""
        else:
            return "Script directory does not exist."
    except FileNotFoundError as err:
            return err

def get_config_snippet(script_name, config):
    # Search for the script name in the config and extract the relevant section
    script_config = config.get(script_name)
    if script_config:   
        # Extract the relevant script configuration snippet
        config_snippet = yaml.dump({script_name: script_config})
        return config_snippet
    # If the script name is not found in the config
    return ''

def lock_script(script_name):
    lock_file = f"/tmp/{script_name}.lck"
    with open(lock_file, "w") as file:
        file.write("")

def unlock_script(script_name):
    lock_file = f"/tmp/{script_name}.lck"
    if os.path.exists(lock_file):
        os.remove(lock_file)

def script_locked(script_name):
    lock_file = f"/tmp/{script_name}.lck"
    if os.path.exists(lock_file):
        return True
    return False

def run_script_name(script_name, config):
    script_data = config.get("extra_scripts", {}).get(script_name)
    log_file = config.get("logging", {}).get("file")
    ts_cmd = f'sed -e "s/^/[$(date +\'%Y-%m-%d %I:%M:%S\')] /"'
    if script_data:
        script_path = script_data.get("script")
        if script_path:
            if script_locked(script_name):
                with open(log_file, 'a') as file:
                    file.write(f"[{datetime.datetime.now()}] [{script_name}] ERROR: Script: 'script_name' locked, already running")
                return f"Script: {script_name} already running."
            # Lock script before run
            lock_script(script_name)
            with open(log_file, 'a') as file:
                    file.write(f"[{datetime.datetime.now()}] Starting Script:'{script_name}' with command:'{script_path}'\n")
            try:
                process = subprocess.Popen(f"{script_path} | {ts_cmd} | tee -a {log_file}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                output, _ = process.communicate()
                output.decode()
            except subprocess.CalledProcessError as e:
                error_output = f"[{datetime.datetime.now()}] [{script_name}] Error:\n{e.output.decode()}\n"
                with open(log_file, 'a') as file:
                    file.write(error_output)
            # Unlock script after run.
            unlock_script(script_name)
        else:
            console_output = f"[{datetime.datetime.now()}] [{script_name}] Error: Script is not defined in the config.yml\n"
            with open(log_file, 'a') as file:
                    file.write(console_output)
    else:
        console_output = f"[{datetime.datetime.now()}] [{script_name}] Error: Script not found in the config.yml\n"
        with open(log_file, 'a') as file:
                    file.write(console_output)

def run_script(script_name, script_path, log_file):
    ts_cmd = f'sed -e "s/^/[$(date +\'%Y-%m-%d %I:%M:%S\')] /"'
    # Acquire the script lock
    with threading.script_lock:
        # Lock script before run
        lock_script(script_name)
        with open(log_file, 'a') as file:
            file.write(f"[{datetime.datetime.now()}] Starting Script:'{script_name}' with command:'{script_path}'\n")
        try:
            process = subprocess.Popen(f"{script_path} | {ts_cmd} | tee -a {log_file}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output, _ = process.communicate()
            output.decode()
        except subprocess.CalledProcessError as e:
            error_output = f"[{datetime.datetime.now()}] [{script_name}] Error:\n{e.output.decode()}\n"
            with open(log_file, 'a') as file:
                file.write(error_output)
        # Unlock script after run.
        unlock_script(script_name)




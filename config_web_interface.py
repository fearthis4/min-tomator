#!/usr/bin/python3
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
from collections import defaultdict

from utils import *
from scripts_manager import *

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'

# Path to the YAML config file
global config_file
global config

# Globals
global console_output
console_output = ''
tail_thread = None

# User authentication form
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Config editing form
class ConfigForm(FlaskForm):
    pass

# Config upload form
class ConfigUploadForm(FlaskForm):
    upload = FileField('Config File', validators=[
        FileRequired(),
        FileAllowed(['yml', 'yaml'], 'Yaml Config Files Only!'),
    ])
    submit = SubmitField('Upload Config')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Get user config settings
    config_user = config['config_web_interface']['username']
    config_pass = config['config_web_interface']['username']
    # User authentication
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        # Perform user authentication here (e.g., check username and password against a database)
        if username == config_user and password == config_pass:
            session['user_authenticated'] = True
            if '_flashes' in session:
                session['_flashes'].clear()
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('login.html', form=form)

@app.route('/', methods=['GET', 'POST'])
def home():
    if session.get('user_authenticated'):
        global config
        config = load_config(config_file_path=config_file)
        hostname = get_hostname()
        services_info = get_services_info()

        return render_template('home.html', hostname=hostname, services_info=services_info)
    else:
        return redirect(url_for('login'))

@app.route('/config', methods=['GET', 'POST'])
def edit_config():
    if session.get('user_authenticated'):
        form = ConfigForm()
        form2 = ConfigUploadForm()
        generate_form_fields(config, form)

        return render_template('config.html', form=form, form2=form2, config=config)
    else:
        return redirect(url_for('login'))

@app.route('/update-config', methods=['POST'])
def update_config():
    if session.get('user_authenticated'):
        form_data = {key: request.form[key].strip() for key in request.form}

        try:
            update_config_values(config, form_data)
            with open(config_file, 'w') as file:
                yaml.safe_dump(config, file, sort_keys=False)
            flash('Config saved successfully', 'success')
        except Exception as e:
            flash(f'Error updating config: {str(e)}', 'error')
    else:
        flash('User authentication required', 'error')
    
    return redirect(url_for('edit_config'))

@app.route('/upload-config', methods=['GET', 'POST'])
def upload_config():
    if session.get('user_authenticated'):
        form = ConfigUploadForm()
        if form.validate_on_submit():
            config_file = form.upload.data
            if config_file and allowed_file(config_file, ["yaml", "yml"]):
                tmp_file_path = f"{ config_file }.tmp"
                config_file.save(tmp_file_path)
                try:
                    if validate_config(tmp_file_path):
                        flash('Config file uploaded successfully and validated.', 'success')
                        roll_config(tmp_file_path=tmp_file_path, target_file_path=config_file)
                        flash('Config file updated successfully.', 'success')
                    else:
                        flash('Invalid config file. Please upload a valid YAML file with the required keys.', 'error')
                except Exception as e:
                    flash(f'Error updating config: {str(e)}', 'error')
                
                return redirect(url_for('edit_config'))
        else:
            flash(f'Form Validation failed..', 'error')
    else:
        flash('User authentication required', 'error')

    return redirect(url_for('edit_config'), form=form)

@app.route('/download/<target>')
def download(target):
    global config_file
    if session.get('user_authenticated'):
        if target == 'config':
            try:
                file_path = config_file
                backup_filename = 'config_backup.yml.zip'
                make_archive(file_path, backup_filename)
                return send_file(backup_filename, as_attachment=True)
            except FileNotFoundError:
                return "Config file not found.", 500
        elif target == 'scripts':
            script_name = request.args.get('script_name')
            if not script_name:
                return "No script name provided", 400
            temp_file = f'./extra_scripts/tmp/{script_name}.zip'
            try:
                err = create_script_package(script_name, config, temp_file)
                if err != "":
                    return f"Package creation failed for '{script_name}', {err}", 400
                else:
                    # Send the zip file for download
                    return send_file(temp_file, as_attachment=True)
            except FileNotFoundError:
                return "Script directory not found.", 401
            finally:
                # Cleanup: Delete the temporary directory and its contents
                shutil.rmtree(os.path.dirname(temp_file))
    else:
        return "", 401

@app.route('/scripts', methods=['GET', 'POST'])
def manage_scripts():
    global config
    if session.get('user_authenticated'):
        scripts_statuses = get_script_statuses(config)
        return render_template('scripts.html', scripts_statuses=scripts_statuses)
    else:
        return redirect(url_for('login'))

@app.route('/update-scripts', methods=['POST'])
def update_scripts():
    global config
    if session.get('user_authenticated'):
        script_statuses = defaultdict(list)
        for script_name, value in request.form.items():
            script_statuses[script_name].append(value)

        updated_statuses = {}
        for script_name, values in script_statuses.items():
            if 'on' in values:
                updated_statuses[script_name] = 'True'
            else:
                updated_statuses[script_name] = values[-1]
        try:
            update_script_statuses(config, updated_statuses)
            with open(config_file, 'w') as file:
                yaml.safe_dump(config, file, sort_keys=False)
            flash('Scripts updated successfully', 'success')
            #flash(f'DEBUG: script statuses: "{updated_statuses}"')
        except Exception as e:
            flash(f'Error updating config: {str(e)}', 'error')
    else:
        flash('User authentication required', 'error')
    return redirect(url_for('manage_scripts'))

@app.route('/add-scripts', methods=['GET', 'POST'])
def add_scripts():
    if session.get('user_authenticated'):
        if request.method == 'POST':
            if 'repo_link' in request.form:
                repo_link = request.form['repo_link']
                try:
                    install_script_git_repo(repo_link)
                    return f"Fetched Git repository: {repo_link}", 500
                except subprocess.CalledProcessError:
                    return f"Error fetching Git repository: {repo_link}", 500
            elif 'package_file' in request.files:
                package_file = request.files['package_file']
                try:
                    unpack_package_file(package_file)
                    config_path = os.path.join('./extra_scripts', 'config.yml')
                    merge_config_with_app(config_path)
                    return "Added package file", 200
                except Exception as e:
                    return f"Error adding package file: {str(e)}"
        return render_template(url_for('manage_scripts'))
    else:
        return "", 401
        
@app.route('/information', methods=['GET', 'POST'])
def information():
    if session.get('user_authenticated'):
        system_info = get_system_info()
        services_info = get_services_info()

        return render_template('info.html', system_info=system_info, services_info=services_info)
    else:
        flash('User authentication required', 'error')
        return redirect(url_for('login'))

@app.route('/debug_console', methods=['GET', 'POST'])
def debug_console():
    if session.get('user_authenticated'):
        return render_template('console.html')
    else:
        flash('User authentication required', 'error')
        return redirect(url_for('login'))
    
@app.route("/run-command", methods=["POST"])
def run_command_handler():
    if session.get('user_authenticated'):
        command = request.form.get("command")
        if command.startswith("run "):
            script_name = command[4:].strip()
            if script_name:
                run_script_name(script_name, config)
        else:
            execute_command(command)
        return "", 204
    else:
        return "", 401

@app.route("/run-script", methods=["POST"])
def run_script_handler():
    global config
    if session.get('user_authenticated'):
        script_name = request.form.get("script_name")
        if script_name:
            run_script_name(script_name, config)
        return "", 204
    else:
        return "", 401

@app.route("/execute-command", methods=["POST"])
def execute_command_handler():
    if session.get('user_authenticated'):
        command = request.form.get("command")
        if command:
            err = execute_command(command)
            if err:
                flash(err, 'error')
        return "", 204
    else:
        return "", 401

@app.route('/tail_log')
def tail_log():
    global config
    if session.get('user_authenticated'):
        try:
            # Run the tail command to get the log lines
            process = subprocess.Popen(['tail', '-n', '300', config['logging']['file']], stdout=subprocess.PIPE)
            output, error = process.communicate()
            if output:
                # Decode the output and return it as a JSON response
                output = output.decode('utf-8')
                return jsonify({'output': output})
            else:
                return jsonify({'output': ''})
        except Exception as e:
            return jsonify({'error': str(e)})
    else:
        return "", 401

@app.route('/toggle-theme', methods=['POST'])
def toggle_theme():
    current_theme = request.cookies.get('theme', 'light')
    new_theme = 'dark' if current_theme == 'light' else 'light'
    referer = request.headers.get('Referer')
    if referer:
        response = redirect(referer)
    else:
        response = redirect('/')
    response.set_cookie('theme', new_theme)
    return response

@app.route('/update', methods=['GET', 'POST'])
def update_server():
    if session.get('user_authenticated'):
        return render_template('update.html')
    else:
        return "", 401

@app.route('/shutdown', methods=['GET', 'POST'])
def shutdown():
    if session.get('user_authenticated'):
        confirm = request.form.get('confirm')
        if confirm == 'true':
            os.system('sudo shutdown -h now')
            flash('Server is shutting down...', "warning")
        else:
            referer = request.headers.get('Referer')
            response = redirect(referer)
            return response
    else:
        return "", 401

# Custom template filter to check if a key has a substring from the word list
@app.template_filter('is_secret_key')
def is_secret_key(key):
    secret_keywords = ['password', 'token', 'secret', 'key']
    for word in secret_keywords:
        if word.lower() in key.lower():
            return True
    return False

def generate_form_fields(config, form_class, parent_key=''):
    for key, value in config.items():
        input_name = f'{parent_key}.{key}' if parent_key else key

        if isinstance(value, dict):
            generate_form_fields(value, form_class, input_name)
        else:
            setattr(form_class, input_name, StringField(input_name, default=value))

# Checks/Updates config file data
def update_config_values(config, form_data, parent_key=''):
    for key, value in config.items():
        input_name = f'{parent_key}.{key}' if parent_key else key

        if isinstance(value, dict):
            update_config_values(value, form_data, input_name)
        else:
            form_value = form_data.get(input_name)
            if form_value is not None:
                form_value = escape(form_value)  # Escaping HTML special characters
                config[key] = form_value
            else:
                raise ValueError(f'Missing form input for key: {input_name}')

# Function to check if the file has allowed extension
def allowed_file(filename, allowed_extensions):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

# Function to validate the config file
def validate_config(file_path):
    try:
        with open(file_path, 'r') as file:
            config = yaml.safe_load(file)
            required_keys = ["config_web_interface", "mqtt", "telegram", "logging"]
            for key in required_keys:
                if key not in config:
                    return False
    except (yaml.YAMLError, FileNotFoundError):
        return False
    return True

def get_script_statuses(config):
    script_statuses = {}
    for script_name, _ in config.get('extra_scripts', {}).items():
        script_statuses[script_name] = config.get(script_name).get('enabled', False)
    return script_statuses

def update_script_statuses(config, script_statuses):
    for script_name, enabled in script_statuses.items():
        if script_name in config.get('extra_scripts', {}):
            if enabled == "True" or enabled == "true":
                config[script_name]['enabled'] = True
            else:
                config[script_name]['enabled'] = False

def get_services_info():
    services_info = {'enabled': [], 'disabled': []}
    for key, value in config.items():
        if key == "logging" or key == "extra_scripts":
            continue
        if isinstance(value, dict):
            service = {'name': key, 'enabled': value.get('enabled', False)}
            if service['enabled']:
                services_info['enabled'].append(service)
            else:
                services_info['disabled'].append(service)
    return services_info

def get_hostname():
    return socket.gethostname()

def get_system_info():
    system_info = {}
    
    # Uptime
    system_info['uptime'] = f"{psutil.boot_time():.2f} seconds"
    
    # Get system details
    system_status = subprocess.check_output(['uname', '-a']).decode().strip()
    system_info['details'] = system_status
    
    # CPU
    cpu_info = {}
    cpu_info['load'] = f"{psutil.cpu_percent()}%"
    cpu_info['temp'] = f"{psutil.sensors_temperatures().get('cpu_thermal')[0].current} °C"
    system_info['cpu'] = cpu_info
    
    # Memory
    mem = psutil.virtual_memory()
    ram_info = {}
    ram_info['total'] = f"{mem.total // (1024 * 1024)} MB"
    ram_info['used'] = f"{mem.used // (1024 * 1024)} MB"
    ram_info['free'] = f"{mem.free // (1024 * 1024)} MB"
    ram_info['free_percentage'] = f"{mem.percent}%"
    system_info['ram'] = ram_info
    
    # Storage
    disk_info = []
    for partition in psutil.disk_partitions():
        disk_usage = psutil.disk_usage(partition.mountpoint)
        disk = {}
        disk['device'] = partition.device
        disk['size'] = f"{disk_usage.total // (1024 * 1024)} MB"
        disk['used'] = f"{disk_usage.used // (1024 * 1024)} MB"
        disk['available'] = f"{disk_usage.free // (1024 * 1024)} MB"
        disk['percentage'] = f"{disk_usage.percent}%"
        disk_info.append(disk)
    system_info['disk_space'] = disk_info
    
    # Network Interfaces
    net_info = []
    for interface, addresses in psutil.net_if_addrs().items():
        net_interface = {}
        net_interface['interface'] = interface
        net_interface['mac_address'] = ""
        net_interface['addresses'] = []
        for address in addresses:
            if address.family == psutil.AF_LINK:
                net_interface['mac_address'] = address.address
            elif address.family == socket.AF_INET:
                net_interface['addresses'].append(address.address)
        net_info.append(net_interface)
    system_info['network_interfaces'] = net_info
    
    return system_info

def sanitize_command(command):
    # Remove any characters that are not alphanumeric or common symbols
    sanitized_command = re.sub(r'[^a-zA-Z0-9_\-./]', '', command)
    return sanitized_command

def command_allowed(command):
    ALLOWED_COMMANDS = ["ip", "ping", "traceroute", "netstat", "ps", "ls"]
    # Catch ';' character for injection
    if ";" in command:
        return False
    # Check for each command in list
    for allowed_command in ALLOWED_COMMANDS:
        if allowed_command in command:
            return True
    # Return False if not in the allowed list    
    return False

def execute_command(command):
    log_file = config.get("logging", {}).get("file")
    command = command.strip()
    if command_allowed(command):
        with open(log_file, 'a') as file:
                file.write(f"[{datetime.datetime.now()}] Running Command:'{command}'\n")
        try:
            process = subprocess.Popen(f"{command} | tee -a {log_file}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output, _ = process.communicate()
            output.decode()
            #output = subprocess.check_output(shlex.split(command), universal_newlines=True)
            #sanitized_output = html.escape(output)
            #log_output = f"[{datetime.datetime.now()}] [Command: {command}]:\n{output}\n"
            #with open(log_file, 'a') as file:
            #    file.write(log_output)
            #return sanitized_output
        except subprocess.CalledProcessError:
            error_output = f"[{datetime.datetime.now()}] [Command: {command}] Error: executing command.\n"
            with open(log_file, 'a') as file:
                file.write(error_output)
            return "Error executing command."
    else:
        error_output = f"[{datetime.datetime.now()}] [Command: {command}] Error: command not allowed!\n"
        with open(log_file, 'a') as file:
                file.write(error_output)
        return "Command not allowed."

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='Target config file', default='config.yml')
    parser.add_argument('-s', '--settingname', help='Target setting name in config file', default="config_web_interface")
    args = parser.parse_args()

    config_file = args.config
    config = load_config(config_file)

    config_target = args.settingname

    app.secret_key = ".."
    # Pull config settings for server
    web_interface_settings = config.get(config_target, {})
    # Pull config data for server
    host = web_interface_settings['host']
    port = web_interface_settings['port']
    # Check if https is enabled, default to false if not specified
    if web_interface_settings.get('https', False):
        # Https is enabled
        app.run(debug=True, host=host, port=port, ssl_context='adhoc')
    else:
        app.run(debug=True, host=host, port=port)
    
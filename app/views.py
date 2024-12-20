from flask import Blueprint, render_template, request, jsonify
import subprocess
import jsbeautifier
import re
import asyncio
import aiohttp
import os
import requests
from time import sleep
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from io import TextIOWrapper
import paramiko
import telnetlib
import sqlite3
import json

# Initialize the Blueprint
app_blueprint = Blueprint("app", __name__)

# Function to run commands with sudo privileges
def run_with_sudo(command):
    """
    Run a shell command with sudo, passing the password automatically.
    """
    password = 'kali'  # Replace with your sudo password
    command = f"echo {password} | sudo -S {command}"  # Pass the password to sudo
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while running the command: {e}")
        return str(e)

@app_blueprint.route("/", methods=["GET", "POST"])
def index():
    """
    Home route to display the IP scanning tool interface.
    """
    results = []  # Store detailed scan results
    error = None
    protocol_result = None
    protocol_error = None

    if request.method == "POST":
        target = request.form.get("target")
        if target:
            try:
                # Run the Nmap scan using subprocess
                print(f"Scanning target: {target}")
                command = f"sudo nmap -p 22-80 {target}"  # Scan ports 22 to 80
                result = subprocess.run(command, shell=True, capture_output=True, text=True)

                # Parse the Nmap output
                output = result.stdout.splitlines()
                open_ports = []
                for line in output:
                    # Identify open ports from Nmap output
                    if "/tcp" in line and "open" in line:
                        parts = line.split()
                        port = parts[0].split('/')[0]  # Extract port number
                        service = parts[2] if len(parts) > 2 else "Unknown"  # Extract service name
                        open_ports.append({"port": port, "service": service})

                # Add results to the results list
                if open_ports:
                    results.append({"IP": target, "State": "Active", "OS": "Unknown", "Open Ports": open_ports})
                else:
                    error = f"No open ports found for {target}."

            except Exception as e:
                error = str(e)

    return render_template("index.html", results=results, error=error, protocol_result=protocol_result, protocol_error=protocol_error)

@app_blueprint.route('/protocol', methods=['POST'])
def protocol_search():
    protocol_or_port = request.form.get('protocol')
    protocol_result = None
    protocol_error = None

    if not protocol_or_port:
        protocol_error = "Input is required."
    else:
        try:
            # Check if input is a protocol name or port number
            if protocol_or_port.isdigit():
                # Input is a port number
                port = int(protocol_or_port)
                tcp_service = subprocess.run(
                    ["getent", "services", str(port), "tcp"], capture_output=True, text=True
                ).stdout.strip()

                udp_service = subprocess.run(
                    ["getent", "services", str(port), "udp"], capture_output=True, text=True
                ).stdout.strip()

                protocol_result = {
                    "Port": port,
                    "TCP Service": tcp_service or "Not found",
                    "UDP Service": udp_service or "Not found"
                }
            else:
                # Input is a protocol name
                tcp_port = subprocess.run(
                    ["getent", "services", protocol_or_port, "tcp"], capture_output=True, text=True
                ).stdout.strip()

                udp_port = subprocess.run(
                    ["getent", "services", protocol_or_port, "udp"], capture_output=True, text=True
                ).stdout.strip()

                protocol_result = {
                    "Protocol": protocol_or_port,
                    "TCP Port": tcp_port or "Not found",
                    "UDP Port": udp_port or "Not found"
                }

        except Exception as e:
            protocol_error = f"An error occurred: {str(e)}"

    return render_template("index.html", protocol_result=protocol_result, protocol_error=protocol_error)

@app_blueprint.route("/exploit/beautify/<int:id>", methods=["GET", "POST"])
def beautify(id=None):
    beautified_js = None
    error = None

    if request.method == 'POST':
        raw_js = request.form.get('raw_js')

        if raw_js:
            try:
                beautifier = jsbeautifier.Beautifier()
                beautified_js = beautifier.beautify(raw_js)
            except Exception as e:
                error = f"An error occurred: {e}"
        else:
            error = "No JavaScript code was provided."

    return render_template('beautify.html', beautified_js=beautified_js, error=error)

@app_blueprint.route("/exploit/dnsenumeration/<int:id>", methods=["GET", "POST"])
def dns_enumeration(id):
    subdomain_output = None  # Initialize the output variable

    if request.method == "POST":
        target_domain = request.form.get("target")

        if not target_domain:
            return f"Target domain is required for ID {id}.", 400

        try:
            print(f"Processing DNS Enumeration for ID: {id}")

            # Run sublist3r using subprocess
            result = subprocess.run(
                ["sublist3r", "-d", target_domain],
                capture_output=True,
                text=True,
                check=True
            )

            # Remove color codes using a regular expression
            clean_output = re.sub(r'\x1b\[[0-9;]*m', '', result.stdout)

            # Extract subdomains from the cleaned result using regex
            subdomains = re.findall(r"\S+\." + re.escape(target_domain), clean_output)

            # Remove duplicates and sort the subdomains
            unique_subdomains = sorted(set(subdomains))

            # Prepare the subdomain output in a table-like format without color codes
            subdomain_output = f"""
            <h3>Subdomain Enumeration Results for {target_domain}</h3>
            <p><strong>Total Unique Subdomains Found:</strong> {len(unique_subdomains)}</p>
            <table class="table table-dark">
                <thead>
                    <tr>
                        <th>Subdomain</th>
                        <th>Status</th>
                        <th>Port</th>
                        <th>Protocol</th>
                    </tr>
                </thead>
                <tbody>
            """
            for subdomain in unique_subdomains:
                subdomain_output += f"""
                    <tr>
                        <td>{subdomain}</td>
                        <td>Not Checked</td>
                        <td>80</td>
                        <td>HTTP</td>
                    </tr>
                """

            subdomain_output += "</tbody></table>"

            return render_template("dnsenumeration.html", id=id, subdomain_output=subdomain_output)

        except subprocess.CalledProcessError as e:
            return f"Error running Sublist3r for ID {id}: {e.stderr}", 500
        except Exception as e:
            return f"An error occurred for ID {id}: {str(e)}", 500

    return render_template("dnsenumeration.html", id=id, subdomain_output=subdomain_output)

# Helper function for AES decryption
def decrypt_aes(encrypted_text, key):
    try:
        encrypted_data = base64.b64decode(encrypted_text)
        cipher = AES.new(key.encode(), AES.MODE_CBC, encrypted_data[:16])  # IV is the first 16 bytes
        decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
        return decrypted_data.decode('utf-8')
    except Exception as e:
        return str(e)

# Route for decryption
@app_blueprint.route("/exploit/decrypt/<int:id>", methods=["GET", "POST"])
def decrypt(id):
    decrypted_text = None
    error_message = None

    if request.method == "POST":
        encoded_text = request.form.get("encoded_text")

        if encoded_text:
            try:
                # Decode Base64
                decoded_bytes = base64.b64decode(encoded_text)
                decrypted_text = decoded_bytes.decode('utf-8')  # Assuming the original text was UTF-8 encoded

            except (base64.binascii.Error, UnicodeDecodeError) as e:
                # If Base64 decoding fails or there is a decoding error
                error_message = "Invalid Base64 input or decoding error."

    return render_template("decrypt.html", decrypted_text=decrypted_text, error_message=error_message)

@app_blueprint.route("/exploit/direnumeration/<int:id>", methods=["GET", "POST"])
def directory_enumeration(id):
    result_output = []  # Initialize the result list
    total_directories = 0  # Counter for the total directories

    if request.method == "POST":
        target_url = request.form.get("target_url")
        wordlist_file = request.files.get("wordlist_file")

        if not target_url or not wordlist_file:
            return f"Target URL and wordlist file are required for ID {id}.", 400

        try:
            print(f"Processing Directory Enumeration for ID: {id}")

            # Read the wordlist file content
            wordlist_content = wordlist_file.read().decode("utf-8")
            wordlist = wordlist_content.splitlines()

            # Run the asynchronous directory enumeration
            async def perform_directory_enumeration(target_url, wordlist):
                results = []
                async with aiohttp.ClientSession() as session:
                    tasks = []
                    for word in wordlist:
                        url = f"{target_url}/{word.strip()}"
                        tasks.append(fetch_url(session, url))
                    responses = await asyncio.gather(*tasks)
                    results = [response for response in responses if response]
                return results

            async def fetch_url(session, url):
                try:
                    async with session.get(url, timeout=5) as response:
                        if response.status in [200, 301, 403, 404]:
                            return {
                                "path": url.split("/")[-1],
                                "status": response.status,
                                "complete_url": url,
                            }
                except Exception as e:
                    print(f"Error fetching URL {url}: {str(e)}")
                return None

            # Run the asynchronous task
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result_output = loop.run_until_complete(perform_directory_enumeration(target_url, wordlist))
            total_directories = len(result_output)

            # Pass results to the HTML template
            return render_template("direnumeration.html", id=id, result_output=result_output, total_directories=total_directories)

        except Exception as e:
            return f"An error occurred for ID {id}: {str(e)}", 500

    return render_template("direnumeration.html", id=id, result_output=result_output, total_directories=total_directories)

@app_blueprint.route("/exploit/bruteforce/<int:id>", methods=["GET", "POST"])
def bruteforce(id):
    if request.method == "POST":
        target_ip = request.form.get("target_ip")
        username_file = request.files.get("username_file")
        password_file = request.files.get("password_file")

        if not (target_ip and username_file and password_file):
            return render_template("bruteforce.html", error="All fields are required.")

        # Process the uploaded files in-memory
        username_list = [line.strip() for line in TextIOWrapper(username_file.stream, encoding='utf-8')]
        password_list = [line.strip() for line in TextIOWrapper(password_file.stream, encoding='utf-8')]

        # Run the brute force attack
        result_output = ssh_bruteforce(target_ip, username_list, password_list)
        return render_template("bruteforce.html", result_output=result_output)

    return render_template("bruteforce.html")


def ssh_bruteforce(target_ip, username_list, password_list):
    success = []
    for username in username_list:
        for password in password_list:
            try:
                # Attempt SSH login using paramiko
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname=target_ip, username=username, password=password, timeout=5)
                
                # If successful, record the credentials
                success.append(f"Success: {username}:{password}")
                ssh.close()
            except paramiko.AuthenticationException:
                continue  # Ignore failed login attempts
            except Exception as e:
                continue  # Ignore other errors for simplicity

    return success if success else ["No valid credentials found."]



@app_blueprint.route('/exploit_xss/<int:id>', methods=['GET', 'POST'])
def exploit_xss(id):
    try:
        if request.method == 'POST':
            # Simulate some processing logic
            output = request.form.get('data', '{}')  # Example input
            json_output = json.loads(output)
            return render_template("xss.html", id=id, result=json_output)
        else:
            return render_template("xss.html", id=id)
    except json.JSONDecodeError as e:
        return render_template("xss.html", id=id, error=f"Failed to parse JSON output: {str(e)}")
# Python script to automate the install of Secret Server and privilege manager
import re
import os
import sys
import time
import socket
import argparse
import subprocess

# Not part of the python standard library
import requests
import psutil
# 'pip install pywin32' needed for the below libraries
import win32api
import win32com.client


# Secret Server executable
# https://updates.thycotic.net/SecretServer/setup.exe

# Secret Server Conenction Manager executable
# https://downloads.cm.thycotic.com/Thycotic.ConnectionManager.WindowsInstaller.msi

# Secret Server Password Reset Server
# https://updates.thycotic.net/PasswordResetServer/setup.exe

# Secret Server application files
# https://updates.thycotic.net/SecretServer/getlatestversion.aspx?alwayslatest=true

# Privilege Manager application files
# https://delinea.center/pmgr/link/AppFilesZip

# Secret Server cli install
# https://docs.thycotic.com/secrets/current/setup/installation/installing-silent-cli


# Define a function to run a powershell or commandline command via subprocess and return the string output
def parse_command(command):
    try:    
        command = subprocess.run(["powershell.exe", "-Command", command], capture_output=True)
        command_output = command.stdout.decode("utf-8")
        command_output = command_output.replace('\n', '')
        command_output = command_output.replace('\r', '')
        
        if command.returncode != 0:
            print(command.stderr)
            return (command.stderr.decode("utf-8"))
        else:
            return command_output
        
    except subprocess.CalledProcessError as e:
        print(e)

        return None

    
# Define a function to install dotnet 4.8 using a powershell script
# Requires a restart
def install_dotnet():
    dotnet_script = """[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
$save_path = "$Env:Temp\\ndp48-web.exe";
Invoke-WebRequest "https://go.microsoft.com/fwlink/?linkid=2088631" -OutFile $save_path;
Start-Process -FilePath $save_path -Args "/q /norestart /ChainingPackage ADMINDEPLOYMENT" -Verb RunAs -Wait;
Remove-Item $save_path"""
    parse_command(dotnet_script)

    return
    

# Define a function to create https binding using a powershell script
def create_binding():
    binding_script = """[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
Import-Module WebAdministration;
$fqdn = [System.Net.Dns]::GetHostByName($env:computerName).hostname;
$cert_path = "cert:\LocalMachine\My";
$certificate = New-SelfSignedCertificate -DnsName $fqdn -CertStoreLocation $cert_path;
$certificate_thumbprint = $certificate.Thumbprint;
New-IISSiteBinding -Name "Default Web Site" -BindingInformation "*:443:" -Protocol https -CertificateThumbPrint $certificate_thumbprint -CertStoreLocation $cert_path"""
    parse_command(binding_script)
    
    return
    

# Define a function to install necessary components of iis
def install_iis():
    iis_script = """[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServer;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WebServerRole;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-DefaultDocument;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-DirectoryBrowsing;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpErrors;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-StaticContent;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpRedirect;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpLogging;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionStatic;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-HttpCompressionDynamic;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-RequestFiltering;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-WindowsAuthentication;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ASPNET45;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-NetFxExtensibility45;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIExtensions;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ISAPIFilter;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementConsole;
Enable-WindowsOptionalFeature -Online -FeatureName IIS-ManagementScriptingTools;
Install-Module -Name IISAdministration -Scope AllUsers -AllowClobber -Force;"""
    parse_command(iis_script)
    
    return

    
# Define a function to download and install microsoft sql dev
def install_sql_dev():
    sql_script = """ """
    parse_command(sql_script)
    
    return
    

# Define a function to get process information for the file path specified
def process_exists(file_path):
    # Initialize return variables
    current_process = None
    process_path = None
    process_pid = None
    # Get the current username
    current_user = os.getlogin()
    # Get all current running processes
    for proc in psutil.process_iter(["pid", "name", "username"]):
        # Get only the processes started by the current user
        process_info = proc.info
        if current_user in str(process_info["username"]):
            # Check to see if the filepath plus name is a legitimate path
            # If so, return path and process name
            if os.path.exists(os.path.abspath(process_info["name"])) is True:
                print("Process exists for: {} with PID: {}".format(process_info["name"], process_info["pid"]))
                process_path = os.path.abspath(process_info["name"])
                current_process = process_info["name"]
                process_pid = process_info["pid"]
                
    return current_process, process_path, process_pid



# Define function to print out progress
def print_progress(iteration, total, width=50):
    percent = ("{0:." + str(1) + "f}").format(100 * (iteration / float(total)))
    filled_width = int(width * iteration // total)
    bar = '█' * filled_width + '-' * (width - filled_width)
    print(f'\rProgress: |{bar}| {percent}% Complete', end = '\r')
    if iteration == total:
        print('\r')


# Define a function to download files
def download_file(url, save_path):
    # Get total file size
    response = requests.get(url, stream=True)

    # Download secret server installer
    total_length = int(response.headers['content-length'])
    current_chunk = 1024
    # Download file
    with open(save_path, 'wb') as file:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                print_progress(current_chunk, total_length)
                file.write(chunk)
                current_chunk += 1024
    # Close file
    file.close()
    
    return


# Define a function to write status to progress file
def write_status(status):
    path = os.path.dirname(os.path.realpath(__file__)) + "\\progress.txt"
    
    if os.path.exists(path) is True:
        with open(path, "a+") as file:
            file.write(status)
            file.write('\n')
    else:
        print("Unable to find progress file.")
        
    return


# Define a function to create a python scheduled task
# If computer, username, domain, and password are set to None,
# The function will use the current domain/user/password and computer (localhost)
def create_task(task_name, argument_list, script_name=None, script_path=None, computer=None, username=None, domain=None, password=None):
    # Set initial variables
    author="i506dk"
    task_path = ""
    # Get path to the python interpreter
    python_path = win32api.GetModuleFileName(0)
    # Get full script path if not supplied
    if script_path is None:
        script_path = __file__
    # Get script name if not supplied
    if script_name is None:
        script_name = os.path.basename(__file__)
    # Get the current working directory of the script
    # Working directory is the directory that the script is in
    working_directory = script_path.replace(script_name, "")

    # Task specifics
    # Set the trigger to user logon
    TASK_TRIGGER_LOGON = 9
    TASK_CREATE_OR_UPDATE = 6
    TASK_ACTION_EXEC = 0
    TASK_LOGON_INTERACTIVE_TOKEN = 3

    # Connect to the task scheduler
    scheduler = win32com.client.Dispatch("Schedule.Service")
    scheduler.Connect(computer, username, domain, password)
    root_folder = scheduler.GetFolder("\\")

    # Define the task
    task_definition = scheduler.NewTask(0)
    task_triggers = task_definition.Triggers

    # Set triggers
    trigger = task_triggers.Create(TASK_TRIGGER_LOGON)
    trigger.Id = "LogonTriggerId"
    # Use the current user
    trigger.UserId = os.environ.get('USERNAME')

    # Define task actions
    task_actions = task_definition.Actions
    action = task_actions.Create(TASK_ACTION_EXEC)
    action.ID = task_name
    action.Path = python_path
    action.WorkingDirectory = working_directory
    # Add python script as first argument
    action.Arguments += script_path
    # Add argument list at the end
    if type(argument_list) is list:
        for argument in argument_list:
            action.Arguments += " " + argument

    # Set task information
    info = task_definition.RegistrationInfo
    info.Author = author
    info.Description = "Scheduled task to run python script at user login."

    # Set additional task settings
    settings = task_definition.Settings
    settings.Hidden = False

    # Create the task
    result = root_folder.RegisterTaskDefinition(task_name, task_definition, TASK_CREATE_OR_UPDATE, "", "", TASK_LOGON_INTERACTIVE_TOKEN)
    # Check to make sure task was created
    if task_name in str(result):
        print("Scheduled task '{}' created, and trigger set to user login.".format(task_name))
        return True
    else:
        print("Failed to create task '{}'".format(task_name))
        return False


# Define a function to restart windows
def restart_windows(arg_list):
    # Print warning message
    print("Restarting in 10 seconds...")
    # For any items that say "awaiting restart" change those to "passed"
    progress_file = os.path.dirname(os.path.realpath(__file__)) + "\\progress.txt"
    if os.path.exists(progress_file) is True:
        with open(progress_file, "r+") as file:
            nonlocal content = file.readlines()

    # Overwrite file
    with open(progress_file, "w") as file:
        # Break items apart and add to dictionary
        for line in content:
            if "awaiting restart" in line:
                new_line = line.replace("awaiting restart", "passed")
                file.write(new_line)
            else:
                file.write(line)
    
    # Set script to re-run at boot with the arguments originally passed to it
    script_name = os.path.basename(__file__)
    # Remove script name/path from arguments
    if arg_list is None:
        arg_list = list(sys.argv)
        for arg in arg_list:
            if script_name in arg:
                arg_list.remove(arg)
                
        create_task("Secret Server Automated Deployment Tool", arg_list) 
    else:
        create_task("Secret Server Automated Deployment Tool", arg_list) 
    
    # Restart system
    os.system("shutdown /r /t 10")
    print("Awaiting restart.")
    exit()
    
    return
    

# Define a function to check whether Secret Server is already installed or not
def previous_install_check():
    print("\nChecking for previous Secret Server installation...")
    # Initialize a counter to count how many variables indicate a previous install
    validation_count = 0
    
    # Check to see if the Secret Server application exists
    secret_server_application = parse_command('Get-WmiObject -Class Win32_Product | Where {$_.Name -like "*secret server*"}')
    if (secret_server_application is None) or (len(secret_server_application) == 0):
        print("  - No previous Secret Server application found.")
    else:
        print("  - Secret Server application found.")
        validation_count += 1
    
    # Check if Secret Server files exist for IIS
    secret_server_files = os.path.exists("C:\\inetpub\\wwwroot\\SecretServer")
    if secret_server_files == True:
        print("  - Secret Server application files found.")
        validation_count += 1
    else:
        print("  - No previous Secret Server application files found.")
        
    # Check to see if registry keys exist for secret server
    secret_server_registry = parse_command("Test-Path 'HKLM:\Software\Thycotic\Secret Server'")
    if secret_server_registry == "True":
        print("  - Secret Server registry keys found.")
        validation_count += 1
    else:
        print("  - No previous Secret Server registry keys found.")
        
    # If 2/3 of the checks come back positive, assume Secret Server is already installed
    if validation_count >= 2:
        print("\n" + str(validation_count) + " / 3 validation checks came back positive indicating that Secret Server is currently installed.")
        return True
    else:
        print("\n" + str(validation_count) + " / 3 validation checks came back positive indicating that Secret Server likely isn't installed.")
        return False


# Define a function to validate SQL database connectivity and credentials
def validate_sql(service_account, service_account_password, hostname, database, port=1433):
    # Check connectivity to the sql server (with powershell)
    #sql_connection = parse_command("(Test-NetConnection -ComputerName {} -Port {}).TcpTestSucceeded".format(hostname, port))
    #if sql_connection == "True":
    #    print("\nConnection to SQL server succeeded.")
    #else:
    #    print("\nConenction failed. Couldn't connect to server.")
        
    # Create socket
    create_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Specify destination or server:port to connect to
    destination = (hostname, port)
    # Test connection
    result = create_socket.connect_ex(destination)
    
    # If 0 is returned, connection was successful
    if result == 0:
       print("\nConnection to SQL server succeeded.")
       sql_connection_pass = True
    else:
        print("\nConenction failed. Couldn't connect to server.")
        sql_connection_pass = False
        
    # Close socket
    create_socket.close()
    
    # Define paths to script, output, and error files
    script_path = os.path.dirname(os.path.realpath(__file__)) + "\\script.ps1"
    output_path = os.path.dirname(os.path.realpath(__file__)) + "\\output.txt"
    error_path = os.path.dirname(os.path.realpath(__file__)) + "\\error.txt"
    
    # Initialize powershell script contents to check sql permissions
    script_content = """$sql_command = "SELECT * FROM fn_my_permissions(NULL, 'DATABASE');"
$sql_connection = New-Object System.Data.SqlClient.SqlConnection
$sql_connection.ConnectionString = 'Data Source="{}";database="{}";Initial Catalog=master;Integrated Security=SSPI;'
$command = new-object system.data.sqlclient.sqlcommand($sql_command, $sql_connection)
$sql_connection.Open()
$adapter = New-Object System.Data.sqlclient.sqlDataAdapter $command
$dataset = New-Object System.Data.DataSet
$adapter.Fill($dataSet) | Out-Null
$sql_connection.Close()
$dataSet.Tables | Format-Table -HideTableHeaders""".format(hostname, database)
    
    # Write powershell to script file
    with open(script_path, "w+") as file:
        # Break items apart and add to dictionary
        file.write(script_content)
    
    # Run script as service account
    sql_command = "Start-Process powershell.exe '{}' -Credential (New-Object System.Management.Automation.PSCredential '{}', (ConvertTo-SecureString '{}' -AsPlainText -Force)) -PassThru -Wait -RedirectStandardOutput '{}' -RedirectStandardError '{}' -WindowStyle hidden".format(
        script_path,
        service_account,
        service_account_password,
        output_path,
        error_path
    )

    # Wait for process to complete
    parse_command(sql_command)
    
    # Output gets written to text file. Read it back in
    if os.path.exists(output_path) is True:
        with open(output_path, "r+") as file:
            nonlocal content = file.readlines()
    else:
        print("Output file not found.")
            
    # If nothing is written to the content file, assume the command failed
    # And check the error file
    if len(content) == 0:
        if os.path.exists(error_path) is True:
            with open(output_path, "r+") as file:
                content = file.readlines()
        else:
            print("Error file not found.")
            
        print("Getting SQL permissions failed with error: ")
        
    else:
        # Clean up permissions
        i = 0
        while i < len(content):
            current_line = content[i]
            current_line = current_line.strip()
            if len(current_line) == 0:
                content.pop(i)
                i -= 1
            else:
                current_line = current_line.replace("database", '')
                current_line = current_line.strip()
                content[i] = current_line
                
            i += 1
        
        # Print out the permissions returned after parsing
        print("\nSql Permissions for service account {}: ".format(service_account))
        for item in content:
            print("  - " + str(item))
        
    # Accounts needs create and view permissions on the database
    if ("CREATE DATABASE" in content) and ("VIEW ANY COLUMN ENCRYPTION KEY DEFINITION" in content) and ("VIEW ANY COLUMN MASTER KEY DEFINITION" in content):
        print("\nService account '{}' has the correct permissions on the database '{}'".format(service_account, database))
        sql_permission_pass = True
    else:
        print("\nService account '{}' does not have the correct permissions on the database '{}'".format(service_account, database))
        sql_permission_pass = False
    
    # Check for errors that show up here
    if (sql_connection_pass is True) and (sql_permission_pass is True):
        print("SQL validation passed. Continuing...")
        
        # Cleanup
        if os.path.exists(output_path) is True:
            os.remove(output_path)
        if os.path.exists(error_path) is True:
            os.remove(error_path)
        if os.path.exists(script_path) is True:
            os.remove(script_path)
            
    else:
        input("SQL validation failed. Exiting...")
        cleanup()
        exit()
    
    return
    
    
# Define a function to cleanup
def cleanup():
    # Search for the registry key
    autorun_key = subprocess.run('reg query "HKEY_CURRENT_USER\\Software\Microsoft\Windows\CurrentVersion\\RunOnce"', capture_output=True)
    autorun_key = autorun_key.stdout.decode("utf-8")
    # If key exists, delete it, if not silently pass
    if autorun_key is not None:
        if len(autorun_key.strip()) > 0:
            # Remove registry key
            run_at_startup_remove(os.path.basename(__file__), user=True)

    # Remove progress file if it exists
    os.path.dirname(os.path.realpath(__file__)) + "\\progress.txt"
    if os.path.exists(os.path.dirname(os.path.realpath(__file__)) + "\\progress.txt") is True:
        os.remove(os.path.dirname(os.path.realpath(__file__)) + "\\progress.txt")
    
    # Remove scheduled task
    subprocess.Popen('schtasks /delete /tn "Secret Server Automated Deployment Tool" /f')

    return
    

# Define a function to install secret server
def install_secret_server(administrator_password, service_account, service_account_password, sql_hostname, database_name = "SecretServer"):
    # Url to setup.exe
    installer_url = "https://updates.thycotic.net/SecretServer/setup.exe"
    # Set download path
    installer = os.path.dirname(os.path.realpath(__file__)) + "\\setup.exe"
    
    try:
        # Download Secret Server
        print("\nDownloading Secret Server installer...")
        download_file(installer_url, installer)
        
        # Create log folder
        log_directory = os.path.dirname(os.path.realpath(__file__)) + "\\Logs"
        if os.path.exists(log_directory) is True:
            # os.walk returns path, directories, and files.
            # Just delete the files
            for contents in os.walk(log_directory):
                for file in contents[2]:
                    current_file = log_directory + "\\" + file
                    #os.chmod(current_file, 0o777)
                    os.remove(current_file)
        else:
            os.mkdir(log_directory)
        
        # Output log file to current working directory
        log_file = log_directory + "\\ss-install.log"

        # Command for installing secret server silently
        ss_command = [
            installer,
            "-q",
            "-s",
            "InstallSecretServer=1",
            "InstallPrivilegeManager=1",
            'SecretServerUserDisplayName="Administrator"',
            'SecretServerUserName="Administrator"',
            "SecretServerUserPassword=" + '"' + administrator_password + '"',
            "SecretServerAppUserName=" + '"' + service_account + '"',
            "SecretServerAppPassword=" + '"' + service_account_password + '"',
            "DatabaseIsUsingWindowsAuthentication=True",
            "DatabaseServer=" + '"' + sql_hostname + '"',
            "DatabaseName=" + '"' + database_name + '"',
            "/l",
            log_file
        ]

        print("\n\nInstalling Secret Server...")
        # Install Secret Server
        installer_process = subprocess.Popen(ss_command)
            
        # Sleep for 10 seconds
        time.sleep(10)
        
        # Check the PID of the Secret Server installer
        # If it is still running, let it do its thing, otherwise continue
        print("\nChecking for installer process...")
        if installer_process.pid is not None:
            print("Installer found running with PID: {}".format(installer_process.pid))
            j = 1
            while psutil.pid_exists(int(installer_process.pid)) is True:
                if j < 5:
                    print("\rInstaller still running" + "."*j, end="")
                    time.sleep(1)
                    j += 1
                else:
                    print("\rInstaller still running" + "."*j, end="")
                    time.sleep(1)
                    while j > 0:
                        sys.stdout.write('\b \b')
                        j -= 1
        else:
            # If no process is found check for errors or failure
            post_check = previous_install_check()
            if post_check is True:
                print("No installer found running. Continuing...")
            else:
                # Assume the install failed and check the event logs
                print("Installation of Secret Server failed.")
                input("Press any key to exit...")
                exit()

        # Print finish message along with url and credentials
        print("\nSecret Server can be accessed at 'https://{}/SecretServer'".format(socket.getfqdn()))
        print("\nLocal administrator account for Secret Server created with username 'administrator'.")
        print("Secret Server installation log files are located at '{}'".format(log_file))
        input("Press any key to exit...")
        
        # Once Secret Server is installed and configured, delete the setup.exe file
        if os.path.exists(installer) is True:
            os.remove(installer)
            
        return True

    except Exception as error:
        print("Failed with error: {}".format(error))

        return False


# Catch first install that may already have site binding
# Define a main function to install all the pieces needed for Secret Server
def main_function(admin_password, service_account, service_account_password, hostname, database="SecretServer"):
    # Get the curent os type
    os_check = parse_command("$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem; $osInfo.ProductType")

    # If 1, this is a normal windows version
    if os_check == '1':
        print("\nNon-server Windows version detected (Windows 10/11). Secret Server should be installed on Windows Server 2016 or newer.")
        print("Exiting...")

    # If 2 or 3, we are on windows server
    elif (os_check == '2') or (os_check == '3'):
        print("\nDetected Windows Server version. Continuing...")

        # Create a text file to check progress
        progress_file = os.path.dirname(os.path.realpath(__file__)) + "\\progress.txt"
        
        # Initialize a dictionary to hold statuses of each item to be installed
        statuses = {}

        # Check if progress file exists, if not create it
        if os.path.exists(progress_file) is True:
            print("Found progress file...")
            with open(progress_file, "r+") as file:
                content = file.readlines()
                # Break items apart and add to dictionary
                for line in content:
                    line = line.strip('\n')
                    item, status = line.split(" = ")
                    statuses[item] = status    
        else:
            with open(progress_file, "w+") as file:
                print("Progress file not found. Creating...")

        # Check for iis
        if statuses.__contains__("iis"):
            # Install iis and related items
            if statuses["iis"] != "passed":
                # Check if IIS is currently installed or not.
                iis_state = parse_command("(Get-WindowsFeature Web-Server).InstallState")
                # Install IIS if not already installed.
                if str(iis_state) == "Installed":
                    print("Internet Information Services (IIS) is installed on this server. Continuing...")
                    # Write iis status to file
                    write_status("iis = passed")
                    statuses["iis"] = "passed"
                    
                    # If IIS is installed, check https site binding
                    https_binding = parse_command('(Get-IISSiteBinding -Name "Default Web Site" -Protocol https).bindingInformation')
                    # Create https binding if it doesn't already exist
                    if "Web site binding 'https' does not exist." in https_binding:
                        print("HTTPS binding does not exist on this server. Creating binding...")
                        create_binding()
                        # Write binding status to file
                        write_status("binding = passed")
                        statuses["binding"] = "passed"
                    else:
                        print("HTTPS binding set to {}. Continuing...".format(https_binding))
                        # Write binding status to file
                        write_status("binding = passed")
                        statuses["binding"] = "passed"
                        
                    # Check for https activation
                    https_activation_state = parse_command("(Get-WindowsFeature NET-WCF-HTTP-Activation45).InstallState")
                    # Install https activation if not already installed
                    if str(https_activation_state) == "Installed":
                        print("HTTP activation is configured on this server. Continuing...")
                        # Write http activation status to file
                        write_status("https_activation = passed")
                        statuses["https_activation"] = "passed"
                    else:
                        print("Installing HTTP activation on this server...")
                        parse_command("Install-WindowsFeature NET-WCF-HTTP-Activation45")
                        # Write http activation status to file
                        write_status("https_activation = passed")
                        statuses["https_activation"] = "passed"
                     
                    # Check for tcp activation
                    tcp_activation_state = parse_command("(Get-WindowsFeature NET-WCF-TCP-Activation45).InstallState")
                    # Install tcp activation if not already installed
                    if str(tcp_activation_state) == "Installed":
                        print("TCP activation is configured on this server. Continuing...")
                        # Write tcp activation status to file
                        write_status("tcp_activation = passed")
                        statuses["tcp_activation"] = "passed"
                    else:
                        print("Installing TCP activation on this server...")
                        parse_command("Install-WindowsFeature NET-WCF-TCP-Activation45")
                        # Write tcp activation status to file
                        write_status("tcp_activation = passed")
                        statuses["tcp_activation"] = "passed"
                        
                else:
                    # Install IIS
                    print("Installing Internet Information Services (IIS) on this server...")
                    install_iis()
                    # Write iis status to file
                    write_status("iis = passed")
                    statuses["iis"] = "passed"
                    
                    # Create HTTPS binding using self signed certificate
                    print("Creating HTTPS binding on this server...")
                    create_binding()
                    # Write binding status to file
                    write_status("binding = passed")
                    statuses["binding"] = "passed"
                    
                    print("Installing HTTP activation on this server...")
                    parse_command("Install-WindowsFeature NET-WCF-HTTP-Activation45")
                    # Write http activation status to file
                    write_status("https_activation = passed")
                    statuses["https_activation"] = "passed"
                    
                    print("Installing TCP activation on this server...")
                    parse_command("Install-WindowsFeature NET-WCF-TCP-Activation45")
                    # Write tcp activation status to file
                    write_status("tcp_activation = passed")
                    statuses["tcp_activation"] = "passed"
             
                
            # Check for https binding
            if statuses.__contains__("binding"):
                # Install https binding
                if statuses["binding"] != "passed":
                    # If IIS is installed, check https site binding
                    https_binding = parse_command('(Get-IISSiteBinding -Name "Default Web Site" -Protocol https).bindingInformation')
                    # Create https binding if it doesn't already exist
                    if "Web site binding 'https' does not exist." in https_binding:
                        print("HTTPS binding does not exist on this server. Creating binding...")
                        create_binding()
                        # Write binding status to file
                        write_status("binding = passed")
                        statuses["binding"] = "passed"
                    else:
                        print("HTTPS binding set to {}. Continuing...".format(https_binding))
                        # Write binding status to file
                        write_status("binding = passed")
                        statuses["binding"] = "passed"
        
            # Check for https activation
            if statuses.__contains__("https_activation"):
                if statuses["https_activation"] != "passed":
                    # Check for https activation
                    https_activation_state = parse_command("(Get-WindowsFeature NET-WCF-HTTP-Activation45).InstallState")
                    # Install https activation if not already installed
                    if str(https_activation_state) == "Installed":
                        print("HTTP activation is configured on this server. Continuing...")
                        # Write http activation status to file
                        write_status("https_activation = passed")
                        statuses["https_activation"] = "passed"
                    else:
                        print("Installing HTTP activation on this server...")
                        parse_command("Install-WindowsFeature NET-WCF-HTTP-Activation45")
                        # Write http activation status to file
                        write_status("https_activation = passed")
                        statuses["https_activation"]
        
            # Check for tcp activation
            if statuses.__contains__("tcp_activation"):
                if statuses["tcp_activation"] != "passed":
                    # Check for tcp activation
                    tcp_activation_state = parse_command("(Get-WindowsFeature NET-WCF-TCP-Activation45).InstallState")
                    # Install tcp activation if not already installed
                    if str(tcp_activation_state) == "Installed":
                        print("TCP activation is configured on this server. Continuing...")
                        # Write tcp activation status to file
                        write_status("tcp_activation = passed")
                        statuses["tcp_activation"] = "passed"
                    else:
                        print("Installing TCP activation on this server...")
                        parse_command("Install-WindowsFeature NET-WCF-TCP-Activation45")
                        # Write tcp activation status to file
                        write_status("tcp_activation = passed")
                        statuses["tcp_activation"] = "passed"
            
        # This should be the deafult case. No progress file, nothing installed.  
        else:
            # Install everything
            # Check if IIS is currently installed or not.
            iis_state = parse_command("(Get-WindowsFeature Web-Server).InstallState")
            # Install IIS if not already installed.
            if str(iis_state) == "Installed":
                print("Internet Information Services (IIS) is installed on this server. Continuing...")
                # Write iis status to file
                write_status("iis = passed")
                statuses["iis"] = "passed"
                
                # If IIS is installed, check https site binding
                https_binding = parse_command('(Get-IISSiteBinding -Name "Default Web Site" -Protocol https).bindingInformation')
                # Create https binding if it doesn't already exist
                if "Web site binding 'https' does not exist." in https_binding:
                    print("HTTPS binding does not exist on this server. Creating binding...")
                    create_binding()
                    # Write binding status to file
                    write_status("binding = passed")
                    statuses["binding"] = "passed"
                else:
                    print("HTTPS binding set to {}. Continuing...".format(https_binding))
                    # Write binding status to file
                    write_status("binding = passed")
                    statuses["binding"] = "passed"
                    
                # Check for https activation
                https_activation_state = parse_command("(Get-WindowsFeature NET-WCF-HTTP-Activation45).InstallState")
                # Install https activation if not already installed
                if str(https_activation_state) == "Installed":
                    print("HTTP activation is configured on this server. Continuing...")
                    # Write http activation status to file
                    write_status("https_activation = passed")
                    statuses["https_activation"] = "passed"
                else:
                    print("Installing HTTP activation on this server...")
                    parse_command("Install-WindowsFeature NET-WCF-HTTP-Activation45")
                    # Write http activation status to file
                    write_status("https_activation = passed")
                    statuses["https_activation"] = "passed"
                 
                # Check for tcp activation
                tcp_activation_state = parse_command("(Get-WindowsFeature NET-WCF-TCP-Activation45).InstallState")
                # Install tcp activation if not already installed
                if str(tcp_activation_state) == "Installed":
                    print("TCP activation is configured on this server. Continuing...")
                    # Write tcp activation status to file
                    write_status("tcp_activation = passed")
                    statuses["tcp_activation"] = "passed"
                else:
                    print("Installing TCP activation on this server...")
                    parse_command("Install-WindowsFeature NET-WCF-TCP-Activation45")
                    # Write tcp activation status to file
                    write_status("tcp_activation = passed")
                    statuses["tcp_activation"] = "passed"
            else:
                # Install IIS
                print("Installing Internet Information Services (IIS) on this server...")
                install_iis()
                # Write iis status to file
                write_status("iis = passed")
                statuses["iis"] = "passed"
                
                # Check https site binding
                https_binding = parse_command('(Get-IISSiteBinding -Name "Default Web Site" -Protocol https).bindingInformation')
                # Create https binding if it doesn't already exist
                if "Web site binding 'https' does not exist." in https_binding:
                    print("HTTPS binding does not exist on this server. Creating binding...")
                    create_binding()
                    # Write binding status to file
                    write_status("binding = passed")
                    statuses["binding"] = "passed"
                else:
                    print("HTTPS binding set to {}. Continuing...".format(https_binding))
                    # Write binding status to file
                    write_status("binding = passed")
                    statuses["binding"] = "passed"
                
                print("Installing HTTP activation on this server...")
                parse_command("Install-WindowsFeature NET-WCF-HTTP-Activation45")
                # Write http activation status to file
                write_status("https_activation = passed")
                statuses["https_activation"] = "passed"
                
                print("Installing TCP activation on this server...")
                parse_command("Install-WindowsFeature NET-WCF-TCP-Activation45")
                # Write tcp activation status to file
                write_status("tcp_activation = passed")
                statuses["tcp_activation"] = "passed"

        # Check for dotnet
        if statuses.__contains__("dotnet_48"):
            if (statuses["dotnet_48"] != "passed") and (statuses["dotnet_48"] != "awaiting restart"):
                # Install dotnet framework 4.8 if not already installed.
                dotnet_check = subprocess.run('reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\Microsoft\\NET Framework Setup\\NDP\\v4\\full" /v version', capture_output=True)
                dotnet_check = dotnet_check.stdout.decode("utf-8")
                dotnet_version = re.search('\d+(\.\d+)+', dotnet_check)
                # Install dotnet 4.8 if it isn't already installed
                # If dotnet is installed, check to make sure it is the correct version
                if dotnet_version is not None:
                    dotnet_version = dotnet_version[0]
                    # Install dotnet 4.8 if not already installed (Other versions don't matter)
                    if "4.8" in dotnet_version:
                        print("Dotnet 4.8 is installed on this server. Continuing...")
                        # Write dotnet status to file
                        write_status("dotnet_48 = passed")
                        statuses["dotnet_48"] = "passed"
                    else:
                        print("Installing Dotnet 4.8 on this server...")
                        install_dotnet()
                        # Write dotnet status to file
                        write_status("dotnet_48 = awaiting restart")
                        # Restart server
                        restart_windows(["-s", hostname, "-d", database, "-sa", service_account, "-sap", service_account_password, "-a", admin_password])
                        
                else:
                    print("Installing Dotnet 4.8 on this server...")
                    install_dotnet()
                    # Write dotnet status to file
                    write_status("dotnet_48 = awaiting restart")
                    # Restart server
                    restart_windows(["-s", hostname, "-d", database, "-sa", service_account, "-sap", service_account_password, "-a", admin_password])
            elif statuses["dotnet_48"] == "awaiting restart":
                # Restart server
                restart_windows(["-s", hostname, "-d", database, "-sa", service_account, "-sap", service_account_password, "-a", admin_password])
            else:
                # Silently pass as dotnet is already installed
                pass
                
        else:
            # Install dotnet framework 4.8 if not already installed.
            dotnet_check = subprocess.run('reg query "HKEY_LOCAL_MACHINE\\SOFTWARE\Microsoft\\NET Framework Setup\\NDP\\v4\\full" /v version', capture_output=True)
            dotnet_check = dotnet_check.stdout.decode("utf-8")
            dotnet_version = re.search('\d+(\.\d+)+', dotnet_check)
            # Install dotnet 4.8 if it isn't already installed
            # If dotnet is installed, check to make sure it is the correct version
            if dotnet_version is not None:
                dotnet_version = dotnet_version[0]
                # Install dotnet 4.8 if not already installed (Other versions don't matter)
                if "4.8" in dotnet_version:
                    print("Dotnet 4.8 is installed on this server. Continuing...")
                    # Write dotnet status to file
                    write_status("dotnet_48 = passed") 
                    statuses["dotnet_48"] = "passed"
                else:
                    print("Installing Dotnet 4.8 on this server...")
                    install_dotnet()
                    # Write dotnet status to file
                    write_status("dotnet_48 = awaiting restart")
                    # Restart server
                    restart_windows(["-s", hostname, "-d", database, "-sa", service_account, "-sap", service_account_password, "-a", admin_password])
            else:
                print("Installing Dotnet 4.8 on this server...")
                install_dotnet()
                # Write dotnet status to file
                write_status("dotnet_48 = awaiting restart")
                # Restart server
                restart_windows(["-s", hostname, "-d", database, "-sa", service_account, "-sap", service_account_password, "-a", admin_password])

        # Check to make sure all prerequisites passed
        if all(statuses[item] == "passed" for item in statuses):
            print("All prerequisites passed.")
        else:
            keys = list(statuses.keys())
            for item in keys:
                if statuses[item] != "passed":
                    print(item + " did not pass validation checks, and has status: " + statuses[item])

  
        # Check to see if secret server is already installed or not
        ss_install = previous_install_check()
        if ss_install is True:
            input("Exiting...")
            cleanup()
        
        # Validate permissions and connectivity for the sql server
        validate_sql(service_account, service_account_password, hostname, database)
        
        # Install Secret Server
        install_complete = install_secret_server(admin_password, service_account, service_account_password, hostname, database)
        if install_complete is True:
            cleanup()
        else:
            print("Installation of Secret Server failed.")
    
    # Don't know what this would be. Assume normal windows variant.
    else:
        print("\nUnknown operating system identified. Secret Server should be installed on Windows Server 2016 or newer.")
        print("Exiting...")
        
    return


# Define function to parse argument passed via the command line
def parse():
    parser = argparse.ArgumentParser(
        usage="{} [-s 'SQL_server_hostname'] [-d 'SQL_database_name'] [-sa 'domain\\service_account'] [-sap 'service_account_password'] [-p 'current_user_password'] [-a 'local_admin_password']".format(os.path.basename(__file__)),
        description="Automate the installation of Secret Server, along with necessary prerequisites."
    )

    # Add argument that contains the hostname of the SQL server to connect to
    parser.add_argument("-s", "--server", dest="server", action="store", type=str, required=False,
        help="The hostname of the SQL server to connect to.")
        
    # Add argument that contains the database name for Secret Server to use
    parser.add_argument("-d", "--database", dest="database", action="store", type=str, required=False,
        help="The name of the SQL database that Secret Server should use. Default is generally 'SecretServer'.")
        
    #    help="The service account username used to connect to the SQL database. Username should be in the format 'domain\\username'.")
    parser.add_argument("-sa", "--service_account", dest="service_account", action="store", type=str, required=False,
        help="The service account username used to connect to the SQL database. Username should be in the format 'domain\\username'.")
        
    # Add argument that contains the password of the service account             
    parser.add_argument("-sap", "--service_account_password", dest="service_account_password", action="store", type=str, required=False,
        help="The password for the service account used to connect to SQL.") 
        
    # Add argument that contains the password of the local administrator account in secret server            
    parser.add_argument("-a", "--administrator", dest="admin_password", action="store", type=str, required=False,
        help="The password for the local administrator account in Secret Server.")
    
    return parser.parse_args()


# Beginning of main
if __name__ == '__main__':
    # Get command line arguments
    args = parse()

    # Check arguments, and if they aren't passed, ask user for them
    # Create a list of argument keys
    argument_keys = vars(args).keys()

    # For each of the arguments, check to see if they are equal to None. 
    # If equal to none, prompt user to input a values
    for key in argument_keys:
        if getattr(args, key) is None:
            if key == "server":
                args.server = input("Please enter the hostname for the SQL server to connect to: ")
            if key == "database":
                args.database = input("Please enter the SQL database Secret Server should use (Default is 'SecretServer'): ")
            if key == "service_account":
                args.service_account = input("Please enter the service account used to connect to SQL. Username should be in the format 'domain\\username': ")
            if key == "service_account_password":
                args.service_account_password = input("Please enter the password for the service account used to connect to SQL: ")
            if key == "admin_password":
                args.admin_password = input("Please enter the password for the local administrator account in Secret Server: ")

    # Call main function
    main_function(args.admin_password, args.service_account, args.service_account_password, args.server, args.database)

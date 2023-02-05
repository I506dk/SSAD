# Python script to automate the install of Secret Server
import re
import os
import sys
import socket
import argparse
import subprocess

# Not part of the python standard library
import requests
# 'pip  install pywin32' needed for the below libraries
import winerror
import win32con
import win32api
import pywintypes

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

# Define the path to the registry key
Startup_Key_Path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"


# Define a function to run a powershell command via subprocess and return the string output
def parse_command(command):
    command_output = subprocess.check_output(["powershell.exe", command]).decode("utf-8")
    command_output = command_output.replace('\n', '')
    command_output = command_output.replace('\r', '')

    return command_output
    
    
# Define a function to install dotnet 4.8 using a powershell script
# Requires a restart
def install_dotnet():
    dotnet_script = """$save_path = "$Env:Temp\ndp48-web.exe";
Start-BitsTransfer -Source 'https://go.microsoft.com/fwlink/?linkid=2088631' -Destination $save_path;
Start-Process -FilePath $save_path -Args "/q /norestart /ChainingPackage ADMINDEPLOYMENT" -Verb RunAs -Wait;
Remove-Item $save_path"""
    parse_command(dotnet_script)
    
    return
    

# Define a function to create https binding using a powershell script
def create_binding():
    binding_script = """$fqdn = [System.Net.Dns]::GetHostByName($env:computerName).hostname;
$cert_path = "cert:\LocalMachine\My";
$certificate = New-SelfSignedCertificate -DnsName $fqdn -CertStoreLocation $cert_path;
$certificate_thumbprint = $certificate.Thumbprint;
New-IISSiteBinding -Name "Default Web Site" -BindingInformation "*:443:" -Protocol https -CertificateThumbPrint $certificate_thumbprint -CertStoreLocation $cert_path"""
    parse_command(binding_script)
    
    return
    
    
# Define a function to download and install microsoft sql dev
def install_sql_dev():
    sql_script = """ """
    parse_command(sql_script)
    
    return


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
    path = os.getcwd() + "\\progress.txt"
    
    if os.path.exists(path) is True:
        with open(path, "a+") as file:
            file.write(status)
            file.write('\n')
    else:
        print("Unable to find progress file.")
        
    return


# Define a function to run an executable at boot
def run_at_startup_set(appname, path=None, user=False):
    # Store the entry in the registry for running the application at startup
    # Open the registry key path for applications that are run at login
    key = win32api.RegOpenKeyEx(
        win32con.HKEY_CURRENT_USER if user else win32con.HKEY_LOCAL_MACHINE,
        Startup_Key_Path,
        0,
        win32con.KEY_WRITE | win32con.KEY_QUERY_VALUE
    )
    # Make sure the application is not already in the registry
    i = 0
    while True:
        try:
            name, _, _ = win32api.RegEnumValue(key, i)
        except pywintypes.error as e:
            if e.winerror == winerror.ERROR_NO_MORE_ITEMS:
                break
            else:
                raise
        if name == appname:
            win32api.RegCloseKey(key)
            return
        i += 1
    # Create a new key
    win32api.RegSetValueEx(key, appname, 0, win32con.REG_SZ, path or win32api.GetModuleFileName(0))
    # Close the key
    win32api.RegCloseKey(key)
    
    return


# Define a function to run a script at boot
def run_script_at_startup_set(appname, user=False):
    # Like run_at_startup_set(), but for source code files
    run_at_startup_set(
        appname,
        # Set the interpreter path (returned by GetModuleFileName())
        # followed by the path of the current Python file (__file__).
        '{} "{}"'.format(win32api.GetModuleFileName(0), __file__),
        user
    )
    
    return


# Define a function to remove a script from runnning at boot
def run_at_startup_remove(appname, user=False):
    # Remove the registry application passed
    key = win32api.RegOpenKeyEx(
        win32con.HKEY_CURRENT_USER if user else win32con.HKEY_LOCAL_MACHINE,
        Startup_Key_Path,
        0,
        win32con.KEY_WRITE
    )
    win32api.RegDeleteValue(key, appname)
    win32api.RegCloseKey(key)
    
    return


# Define a function to restart windows
def restart_windows():
    # Print warning message
    print("Restarting in 5 seconds...")
    # For any items that say "awaiting restart" change those to "passed"
    if os.path.exists(progress_file) is True:
        with open(progress_file, "r+") as file:
            content = file.readlines()

    # Overwrite file
    with open(progress_file, "w") as file:
        # Break items apart and add to dictionary
        for line in content:
            if "awaiting restart" in line:
                new_line = line.replace("awaiting restart", "passed")
                file.write(new_line)
            else:
                file.write(line)
    
    # Set script to re-run at boot
    run_script_at_startup_set(os.path.basename(__file__), user=True)
    
    # Restart system
    os.system("shutdown /r /t 10")
    
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
    os.getcwd() + "\\progress.txt"
    if os.path.exists(os.getcwd() + "\\progress.txt") is True:
        os.remove(os.getcwd() + "\\progress.txt")

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
        print("Exiting...")
        cleanup()
        exit()
    else:
        print("\n" + str(validation_count) + " / 3 validation checks came back positive indicating that Secret Server likely isn't installed.")
        
    return


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
    script_path = os.getcwd() + "\\script.ps1"
    output_path = os.getcwd() + "\\output.txt"
    error_path = os.getcwd() + "\\error.txt"
    
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

    subprocess.check_output(["powershell.exe", sql_command])
    
    # Output gets written to text file. Read it back in
    if os.path.exists(output_path) is True:
        with open(output_path, "r+") as file:
            content = file.readlines()
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
        print(content)
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
            
    # Cleanup
    if os.path.exists(output_path) is True:
        os.remove(output_path)
    if os.path.exists(error_path) is True:
        os.remove(error_path)
    if os.path.exists(script_path) is True:
        os.remove(script_path)
    
    if (sql_connection_pass is True) and (sql_permission_pass is True):
        print("SQL validation passed. Continuing...")
    else:
        print("SQL validation failed. Exiting...")
        cleanup()
        exit()
    
    return
    

# Define a function to install secret server
def install_secret_server(administrator_password, service_account, service_account_password, sql_hostname, database_name = "SecretServer"):
    # Url to setup.exe
    installer_url = "https://updates.thycotic.net/SecretServer/setup.exe"
    # Set download path
    installer = os.getcwd() + "\\setup.exe"
    # Download Secret Server
    print("\nDownloading Secret Server installer...")
    download_file(installer_url, installer)
    
    # Create log folder
    log_directory = os.getcwd() + "\\Logs"
    if os.path.exists(log_directory) is True:
            os.remove(log_directory)
            os.mkdir(log_directory)
    else:
            os.mkdir(log_directory)
    
    # Output log file to current working directory
    log_file = log_directory + "\\ss-install.log"

    # Command for installing secret server silently
    ss_command = '{} -q -s InstallSecretServer=1 InstallPrivilegeManager=1 ' \
'SecretServerUserDisplayName="Administrator" SecretServerUserName="Administrator" SecretServerUserPassword="{}" ' \
'SecretServerAppUserName="{}" SecretServerAppPassword="{}" ' \
'DatabaseIsUsingWindowsAuthentication=True DatabaseServer="{}" DatabaseName="{}" /l  "{}"'.format(installer, administrator_password, service_account, service_account_password, sql_hostname, database_name, log_file)
    
    # Run installer
    print("\nInstalling Secret Server...")
    os.system(ss_command)

    # Print finish message along with url and credentials
    print("\nSecret Server can be accessed at 'https://{}/SecretServer'".format(socket.getfqdn()))
    print("\nAdministrator credentials for Secret Server are 'administrator' with password '{}'".format(administrator_password))
    print("Secret Server installation log file located at '{}'".format(log_file))
    if os.path.exists(installer) is True:
        os.chmod(installer, 0o777)
        os.remove(installer)

    return


def main_function(admin_password, username, password, hostname, database="SecretServer"):
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
        progress_file = os.getcwd() + "\\progress.txt"
        
        # Initialize a dictionary to hold statuses of each item to be installed
        statuses = {}

        # Check if progress file exists, if not create it
        if os.path.exists(progress_file) is True:
            with open(progress_file, "r+") as file:
                content = file.readlines()
                # Break items apart and add to dictionary
                for line in content:
                    line = line.strip('\n')
                    item, status = line.split(" = ")
                    statuses[item] = status    
        else:
            with open(progress_file, "w+") as file:
                pass

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
                    parse_command("Install-WindowsFeature -name Web-Server -IncludeManagementTools -IncludeAllSubFeature")
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
                parse_command("Install-WindowsFeature -name Web-Server -IncludeManagementTools -IncludeAllSubFeature")
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

        # Check for dotnet
        if statuses.__contains__("dotnet_48"):
            if statuses["dotnet_48"] != "passed":
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
                        restart_windows()
                else:
                    print("Installing Dotnet 4.8 on this server...")
                    install_dotnet()
                    # Write dotnet status to file
                    write_status("dotnet_48 = awaiting restart")
                    # Restart server
                    restart_windows()         
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
                    restart_windows()
            else:
                print("Installing Dotnet 4.8 on this server...")
                install_dotnet()
                # Write dotnet status to file
                write_status("dotnet_48 = awaiting restart")
                # Restart server
                restart_windows()

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
        
        # Validate permissions and connectivity for the sql server
        validate_sql(username, password, hostname, database)
        
        install_secret_server(admin_password, username, password, hostname, database)
    
    # Don't know what this would be. Assume normal windows variant.
    else:
        print("\nUnknown operating system identified. Secret Server should be installed on Windows Server 2016 or newer.")
        print("Exiting...")
        
    return


# Define function to parse argument passed via the command line
def parse():
    parser = argparse.ArgumentParser(
        usage="{} [-s 'SQL_server_hostname'] [-d 'SQL_database_name'] [-u 'domain\\service_account'] [-p 'service_account_password'] [-a 'local_admin_password']".format(os.path.basename(__file__)),
        description="Automate the installation of Secret Server, along with necessary prerequisites."
    )

    # Add argument that contains the hostname of the SQL server to connect to
    parser.add_argument("-s", "--server", dest="server", action="store", type=str, required=False,
        help="The hostname of the SQL server to connect to.")
        
    # Add argument that contains the database name for Secret Server to use
    parser.add_argument("-d", "--database", dest="database", action="store", default="SecretServer", type=str, required=False,
        help="The name of the SQL database that Secret Server should use. Default is 'SecretServer'.")
        
    # Add argument that contains the username of the service account
    parser.add_argument("-u", "--username", dest="username", action="store", type=str, required=False,
        help="The service account username used to connect to the SQL database. Username should be in the format 'domain\\username'.")
        
    # Add argument that contains the password of the service account             
    parser.add_argument("-p", "--password", dest="password", action="store", type=str, required=False,
        help="The password for the service account used to connect to SQL.")
        
    # Add argument that contains the password of the service account             
    parser.add_argument("-a", "--administrator", dest="admin_password", action="store", type=str, required=False,
        help="The password for the local administrator account in Secret Server.")
        
    return parser.parse_args()


# Beginning of main
if __name__ == '__main__':
    # Get command line arguments
    args = parse()
    
    # Check arguments, and if they aren't passed, ask user for them
    # Create a dictionary of the arguments.
    argument_dictionary = vars(args)

    # For each of the arguments, check to see if they are equal to None. 
    # If equal to none, prompt user to input a values
    for key in argument_dictionary.keys():
        if argument_dictionary[key] is None:
            #print("{} is None.".format(key))
            if key == "server":
                argument_dictionary[key] = input("Please enter the hostname for the SQL server to connect to: ")
            if key == "database":
                argument_dictionary[key] = input("Please enter the SQL database Secret Server should use (Default is 'SecretServer'): ")
            if key == "username":
                argument_dictionary[key] = input("Please enter the service account used to connect to SQL. Username should be in the format 'domain\\username': ")
            if key == "password":
                argument_dictionary[key] = input("Please enter the password for the service account used to connect to SQL: ")
            if key == "admin_password":
                argument_dictionary[key] = input("Please enter the password for the local administrator account in Secret Server: ")
                
    # Initialize variables
    server = argument_dictionary["server"]
    database = argument_dictionary["database"]
    username = argument_dictionary["username"]
    password = argument_dictionary["password"]
    admin_password = argument_dictionary["admin_password"]

    # Call main function
    main_function(admin_password, username, password, server, database)


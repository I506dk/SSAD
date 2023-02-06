# SSAD - Secret Server Automated Deployments

![secret_server](https://user-images.githubusercontent.com/33561466/216741532-18d4c459-211e-484d-a69f-838d3ae1fee1.png)

#### A python script to automate Secret Server deployments.

## Features
- Automatically download the latest version of Secret Server
- Install prerequisites for Secret Server like IIS and dotnet 4.8
- Configure connection between Secret Server application and on-premise MS SQL server
- Supports Windows Server 2016 or newer

## Dependencies
- [Pywin32](https://pypi.org/project/pywin32/) - Python for Window Extensions
- [Requests](https://pypi.org/project/requests/) - Python HTTP for Humans

## Installation
**Download the latest release of python below:**

[![Python Latest](https://img.shields.io/badge/python-latest-blue.svg)](https://www.python.org/downloads/windows/)

**Download and install Pip using the following commands:**
```
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
```
**Dependencies can be installed using requirements.txt:**
```
pip install -r requirements.txt
```
**Or individually installed via Pip:**
```
pip install pywin32
pip install requests
```

## Usage
To run SSAD for the first time:
```
python SSAD.py
```
This will configure Secret Server, and require user interaction

Arguments can be specified to the script if an automated installation is wanted.

(***-h or --help***) - will display the help screen.

- Examples: ```python SSAD.py -h``` or ```python SSAD.py --help```

(***-s or --server***)  - the hostname of the SQL server to connect to.

- Examples: ```python SSAD.py -s``` or ```python SSAD.py --server```

(***-d or --database***) - the name of the database Secret Server should use. ('SecretServer' is generally the default)

- Examples: ```python SSAD.py -d``` or ```python SSAD.py --database```

(***-u or --username***) - the username of the service account used to connect to the SQL database. Username should be in te format 'domain\username'.

- Examples: ```python SSAD.py -u``` or ```python SSAD.py --username```

(***-p or --password***) - the password for the service account being used to connect to SQL.

- Examples: ```python SSAD.py -p``` or ```python SSAD.py --password```

(***-a or --administrator***) - the password for the local administrator account created in Secret Server.

- Examples: ```python SSAD.py -a``` or ```python SSAD.py --administrator```

REMINDER - You can use multiple arguments as long as they aren't -h or --help (Those will default to showing the help screen then exiting)

Example run using arguments:
```
python SSAD.py -s my-sql-server -d SecretServer -u test.domain\service_account -p service_password -a admin_password
```

## To Do
- [ ] Create function to remotely install and configure MS SQL (SQL express, and SQL Dev versions)
- [ ] Add option to create the necessary service accounts to run basica Secret Server functionality
- [ ] Automate the setup of distributed engines on remote machines (if possible)
- [ ] Automate the setup of RabbitMQ and site connectors
- [ ] Add uninstall option if previous install is found

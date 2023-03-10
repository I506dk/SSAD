# SSAD - Secret Server Automated Deployments

![secret_server](https://user-images.githubusercontent.com/33561466/216741532-18d4c459-211e-484d-a69f-838d3ae1fee1.png)

#### A python script to automate Secret Server deployments.

[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
![CodeQL](https://github.com/I506dk/SSAD/workflows/CodeQL/badge.svg)
![Latest version](https://github.com/i506dk/SSAD/actions/workflows/versioning.yml/badge.svg)

## Features
- Automatically download the latest version of Secret Server
- Install prerequisites for Secret Server like IIS and dotnet 4.8
- Configure connection between Secret Server application and on-premise MS SQL server
- Supports Windows Server 2016 or newer

## Dependencies
- [Pywin32](https://pypi.org/project/pywin32/) - Python for Window Extensions
- [Psutil](https://pypi.org/project/psutil/) - Cross-platform lib for process and system monitoring in Python
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
pip install psutil
pip install requests
```

## Usage
To run ssad.py for the first time:
```
python ssad.py
```
or
```
ssad.exe
```
This will configure Secret Server, and require user interaction

Arguments can be passed to the script or executable if an automated installation is wanted.

(***-h or --help***) - will display the help screen.

- Examples: ```python ssad.py -h``` or ```python ssad.py --help```

(***-s or --server***)  - the hostname of the SQL server to connect to.

- Examples: ```python ssad.py -s``` or ```python ssad.py --server```

(***-d or --database***) - the name of the database Secret Server should use. ('SecretServer' is generally the default)

- Examples: ```python ssad.py -d``` or ```python ssad.py --database```

(***-sa or --service_account***) - the username of the service account used to connect to the SQL database. Username should be in the format 'domain\username'.

- Examples: ```python ssad.py -sa``` or ```python ssad.py --service_account```

(***-sap or --service_account_password***) - the password for the service account being used to connect to SQL.

- Examples: ```python ssad.py -sap``` or ```python ssad.py --service_account_password```

(***-a or --administrator***) - the password for the local administrator account created in Secret Server.

- Examples: ```python ssad.py -a``` or ```python ssad.py --administrator```

REMINDER - You can use multiple arguments as long as they aren't -h or --help (Those will default to showing the help screen then exiting)

Example run using arguments:
```
python ssad.py -s my-sql-server -d SecretServer -sa test.domain\service_account -sap service_password -a admin_password
```
or
```
ssad.exe -s my-sql-server -d SecretServer -sa test.domain\service_account -sap service_password -a admin_password
```

## Troubleshooting
If the executable doesn't open or doesn't start, right click the executable and select properties.
At the bottom right of the properties windows, check the box next to "Unblock" to allow the executable to run.

![exe_properties](https://user-images.githubusercontent.com/33561466/221655835-0019c865-2a61-467f-bf06-c00fcb589b2c.png)

## To Do
- [ ] Create function to remotely install and configure MS SQL (SQL express, and SQL Dev versions)
- [ ] Add option to create the necessary service accounts to run basic Secret Server functionality/tasks
- [ ] Automate the setup of distributed engines on remote machines (if possible)
- [ ] Automate the setup of RabbitMQ and site connectors
- [ ] Add uninstall option if previous install is found

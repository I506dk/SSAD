# SSAD - Secret Server Automated Deployments

![secret_server](https://user-images.githubusercontent.com/33561466/216741473-66617b77-647c-4bcf-93d0-397809b3e916.png)

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
**Pip comes with newer versions of python**
```
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
```
**Dependencies can manually be installed using requirements.txt:**
```
pip install -r requirements.txt
```
**Or individually installed via Pip:**
```
pip install pywin32
pip install requests
```

## To Do


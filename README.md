# Honeypot Project

[![](https://visitcount.itsvg.in/api?id=whxitte&label=Repo%20Views%20Count&color=0&icon=5&pretty=false)](https://visitcount.itsvg.in) [!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/whxitte)



A simple honeypot implementation to capture and monitor malicious activity. This project uses Flask to create a vulnerable web application and sets up an SSH service for attackers to interact with. It includes logging and monitoring scripts to track and analyze the activity.

**_Project Ongoing...⌛_**

![honeypotrun](https://github.com/user-attachments/assets/ad39a6f7-fcfc-4052-a0de-d88deba95d44)


## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Setup](#setup)
- [Usage](#usage)
- [Monitoring](#monitoring)
- [Deployment](#deployment)
- [Notes](#notes)
- [License](#license)

## Features

- Flask-based vulnerable web application
- SSH service configured with weak credentials
- Logging of commands executed via the web application
- Real-time monitoring of honeypot logs
- More features coming soon...⌛

0. **Pre Setup**
   
   Create a new user on your system for making that account as the Honeypot.
   
      sudo useradd -m -s /bin/bash vulnerableuser # change vulnerable user to your desired username
      sudo passwd vulnerableuser  # Set a weak password like 'password123 or admin or root'
   


## Installation

1. **Clone the repository:**

    ```bash
    git clone https://github.com/whxitte/Honeypot.git
    cd Honeypot
    ```

2. **Create and activate a Python virtual environment:**

    ```bash
    python -m venv honeypot-env
    source honeypot-env/bin/activate  # For Windows use `honeypot-env\Scripts\activate`
    ```

3. **Install the required Python packages:**

    ```bash
    pip install -r requirements.txt
    ```

4. **Install and configure SSH:**

    ```bash
    sudo apt-get install openssh-server
    sudo nano /etc/ssh/sshd_config
    ```

    Edit the SSH configuration file (`/etc/ssh/sshd_config`) to allow password authentication. Add or modify the following lines:

    ```
    PermitRootLogin yes
    PasswordAuthentication yes
    PermitEmptyPasswords yes  # Optional, but increases vulnerability
    ```

    Restart the SSH service:

    ```bash
    sudo systemctl restart ssh
    ```

## Setup

1. **Run the Flask application and SSH service:**

    ```bash
    sudo su
    ./run_honeypot.sh
    ```

2. **Monitor logs in real-time:**

    ```bash
    >> tail -f /var/log/auth.log  # For SSH logs
    or
    >> sudo journalctl -u ssh -f (if above command for ssh not works)
    or check ssh log in your system / monitor it live 
    
    >> tail -f /var/log/honeypot.log  # For Flask app logs
    ```

## Usage

- Access the vulnerable web application at [http://localhost](http://localhost)
- Use the `/vulnerable` endpoint to execute commands. For example:

    ```bash
    http://localhost/vulnerable?cmd=ls
    ```

- The output of commands and any errors will be logged in `/var/log/honeypot.log`.

## Monitoring

To monitor the honeypot activity, you can use the `monitor_honeypot.py` script:

    ```bash
    python monitor_honeypot.py
    ```

This script will print new log entries in a formatted table in real-time.

## Deployment

### Quick cloud deploy (Render / Railway)

This repo is deployment-ready with:
- `Procfile` (`gunicorn ... wsgi:app`)
- `wsgi.py` entry point
- production dependencies in `requirements.txt`

Set these environment variables in your platform:

```bash
FLASK_SECRET_KEY=replace_with_long_random_secret
MONGODB_URI=your_mongodb_connection_string
MONGODB_DB=honeypot
HONEYPOT_LOG_FILE=honeypot.log
# Optional integrations:
ALERT_WEBHOOK_URL=https://your-webhook-endpoint
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
```

Start command (if your platform asks explicitly):

```bash
gunicorn -w 2 -b 0.0.0.0:$PORT wsgi:app
```

### Deploy on a Linux VM (systemd + nginx)

```bash
git clone <your-repo-url>
cd Honeypot
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export FLASK_SECRET_KEY="replace_with_long_random_secret"
gunicorn -w 2 -b 127.0.0.1:8000 wsgi:app
```

Then reverse-proxy with nginx from `:80`/`:443` to `127.0.0.1:8000`.

## Notes

- Make sure to adjust permissions and configurations based on your security needs.
- This setup is intentionally vulnerable for educational purposes and should not be used in a production environment.



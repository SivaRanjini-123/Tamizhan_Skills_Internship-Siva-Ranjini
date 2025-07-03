# Tamizhan Skills Internship Projects - Siva Ranjini

This repository contains all 8 projects completed as part of the Tamizhan Skills Internship Program. Each project demonstrates skills in various areas of Python programming, web development, cybersecurity, and data analysis.

**Video Demonstration:** [Link to My Project Walkthrough Video](**[https://drive.google.com/file/d/1ZIw44z62X4UAcM-7yhw7L5RMwBlZQaID/view?usp=sharing]**)

---

## Table of Contents

* [Project 1: Phishing Detection](#project-1-phishing-detection)
* [Project 2: Password Checker Application](#project-2-password-checker-application)
* [Project 3: Keylogger Implementation](#project-3-keylogger-implementation)
* [Project 4: Port Scanner](#project-4-port-scanner)
* [Project 5: Ransomware Simulator](#project-5-ransomware-simulator)
* [Project 6: Secure Chat Application](#project-6-secure-chat-application)
* [Project 7: SQL Injection Demonstration](#project-7-sql-injection-demonstration)
* [Project 8: Wi-Fi Network Scanner](#project-8-wi-fi-network-scanner)

---

## Project Details

### Project 1: Phishing Detection
Problem Statement:
Phishing websites trick users into entering personal data, leading
to identity theft and fraud.
Objective:
Create a script that detects potentially harmful URLs using rulebased logic or machine learning techniques.
Requirements:
Python
URL dataset (legitimate & phishing)
Scikit-learn (for ML version)
Pandas, Regex (for rule-based version)
Tkinter (optional GUI)
Expected Outcome:
A lightweight tool that flags suspicious URLs and helps users avoid phishing attacks
* **Key Features/Learnings:**
    * [ Implemented a machine learning model for classification.]
    * [ Performed data analysis on phishing datasets.]
    * [ Model saved using `joblib` for future use.]
* **Files:** `Phishing_Detection_Analysis.ipynb`, `phishing_detection_model.joblib`, `phishing_dataset.csv`

### Project 2: Password Checker Application
Problem Statement:
Weak passwords are a major reason for data breaches.
Objective:
Develop a GUI-based tool that analyzes passwords and provides
strength feedback and improvement suggestions.
Requirements:
Python
Tkinter for GUI
Regex for pattern matching
NLTK (optional for dictionary word detection)
Expected Outcome:
An interactive app that informs users if their password is strong or weak and recommends stronger alternatives.
* **Key Features/Learnings:**
    * [ Developed an application to assess password strength.]
    * [ Provided visual feedback on password categories (weak, moderate, strong).]
* **Files:** `password_checker_app.ipynb`, `password_checker_moderatepassword_img.png`, `password_checker_strongpassword_img.png`, `password_checker_weakpassword_img.png`

### Project 3: Keylogger Implementation
Problem Statement:
Understanding how keyloggers work helps develop better security
measures.
Objective:
Create a simple keylogger using Python for ethical and
educational demonstration only
Requirements:
Python
pynput library
File system access for logging
Disclaimer to ensure ethical use
Expected Outcome:
A working keylogger that logs keystrokes to a file, strictly for ethical testing and awareness.
* **Key Features/Learnings:**
    * [ Demonstrated how a basic keylogger works for educational purposes.]
    * [ Recorded keystrokes to a log file.]
* **Files:** `keylogger_Implementation.ipynb`, `keylog.txt`

### Project 4: Port Scanner
Problem Statement:
Network ports are entry points for services; open or vulnerable
ports can be exploited.
Objective:
Build a port scanner to detect open ports on a given IP address or
website.
Requirements:
Python
socket and threading modules
Command-line interface
Expected Outcome:
A script that lists open ports and helps in basic vulnerability assessment of a network.
* **Key Features/Learnings:**
    * [ Developed a tool to identify open ports on a target system.]
    * [ Explored network communication basics.]
* **Files:**  `Port_Scanner_Analysis.ipynb`

### Project 5: Ransomware Simulator
Problem Statement:
Ransomware is a growing cybersecurity threat encrypting user
files for ransom.
Objective:
Simulate ransomware behavior by encrypting files in a folder and
decrypting them with the correct key (education only).
Requirements:
Python
Cryptography module (Fernet)
Sample files/folder
Safety disclaimer
Expected Outcome:
A basic educational demo that encrypts and decrypts files to illustrate how ransomware works.
* **Key Features/Learnings:**
    * [ Simulated basic encryption/decryption (for educational purposes, not actual malicious intent).]
    * [ Understood the principles behind ransomware attacks.]
* **Files:** `Ransomware_Simulator.ipynb`, `test_files/dummy1.txt`, `test_files/dummy2.txt`

### Project 6: Secure Chat Application
Problem Statement:
Most chat apps don’t offer end-to-end encryption by default.
Objective:
Develop a secure messaging application that allows encrypted
text communication between two users.
Requirements:
Python
Socket programming
PyCryptodome or RSA module for encryption
GUI (optional with Tkinter or PyQt)
Expected Outcome:
A basic yet functional chat tool with end-to-end encryption, suitable for internal use or demonstrations.
* **Key Features/Learnings:**
    * [ Implemented a client-server chat application.]
    * [ Explored secure communication principles.]
* **Files:**  `Secure_Chat_App_Analysis.ipynb`, `chat_client.py`, `chat_server.py`

### Project 7: SQL Injection Demonstration
Problem Statement:
Many web apps are vulnerable to SQL injection attacks due to
poor input validation.
Objective:
Simulate a web-based SQL injection vulnerability and
demonstrate how to fix it.
Requirements:
PHP or Python Flask
MySQL or SQLite
Simple login form.
Awareness material on safe coding practices
Expected Outcome:
A vulnerable app that clearly shows how SQL injection works and how to protect against it.
* **Key Features/Learnings:**
    * [ Built a vulnerable web application.]
    * [ Demonstrated common SQL injection techniques.]
    * [ Showcased methods to prevent SQL injection (e.g., parameterized queries).]
* **Files:** `app.py`, `init_db.py`, `requirements.txt` , `templates/dashboard.html`, `templates/login.html`

### Project 8: Wi-Fi Network Scanner
Problem Statement:
Users often need to check available networks and their signal
strength for optimal connectivity.
Objective:
Create a scanner that lists nearby Wi-Fi networks with basic
information such as signal strength.
Requirements:
Python
subprocess or os module (Linux/Windows)
⚫ wifi or pywifi library (platform-dependent)
Expected Outcome:
A script or app that scans and displays available Wi-Fi networks, helping users choose the best one.
* **Key Features/Learnings:**
    * [ Scans and displays available Wi-Fi networks.]
    * [ Gathers information like SSID, BSSID, Signal Strength, Channel, Authentication method.]
    * [ Demonstrated use of `pywifi` library for network interaction.]
* **Files:** `wifi_scanner.py`, `wifi_networks_screenshot.png`

---

## How to Run These Projects

Each project is designed to be run in its own isolated Python virtual environment.

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/SivaRanjini-123/Tamizhan_Skills_Internship-Siva-Ranjini.git](https://github.com/SivaRanjini-123/Tamizhan_Skills_Internship-Siva-Ranjini.git)
    cd Tamizhan_Skills_Internship-Siva-Ranjini
    ```
2.  **Navigate to a specific project folder:**
    ```bash
    cd Project_X_Name
    ```
    (e.g., `cd Project_7_SQL_Injection`)
3.  **Create and activate a virtual environment:**
    ```bash
    python -m venv venv
    .\venv\Scripts\activate
    ```
4.  **Install dependencies:**
    * If a `requirements.txt` file exists in the project folder:
        ```bash
        pip install -r requirements.txt
        ```
    * If no `requirements.txt` is provided, you may need to install the mentioned libraries manually (e.g., `pip install Flask`).
5.  **Run the project:**
    * For Python scripts: `python your_script_name.py`
    * For Jupyter Notebooks: `jupyter notebook your_notebook_name.ipynb`

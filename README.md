# Ephor

## Overview
Ephor is a clipboard security agent for macOS that helps prevent accidental credential leaks by monitoring paste events. Designed for security-conscious users and developers, it integrates seamlessly with your workflow to detect sensitive data and alert you before it is pasted into a browser.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Folder Structure](#folder-structure)
- [Installation](#installation)
- [Running Ephor](#running-ephor)
- [Building a Standalone Executable](#building-a-standalone-executable)
- [License](#license)

## Features

- **Monitors Paste Events:** Uses Quartz event taps to detect global CMD+V events.
- **Secret Detection:** Loads and compiles regex rules from YAML files located in the `rules/` folder.
- **User Notification:** Displays an AppleScript popup alert if sensitive data is pasted in a recognized browser.
- **User Options:** The popup offers two choices—clear the clipboard or continue pasting.

## Requirements

- **Python 3.x**
- **Packages:**  
  - `pyperclip`  
  - `pyobjc`  
  - `pyyaml`  
  - (Optional for building) `PyInstaller`

## Folder Structure

Ensure your project directory is organized as follows:
```
ephor git:(main) ✗ ls
LICENSE          README.md        build            dist             ephor.py         ephor.spec       main.py          requirements.txt rules            venv
```

## Installation

- **Clone or download** the project into a directory (e.g., `ephor/`).

- **Install the required packages** using pip. You can use a virtual environment if desired:

```
# (Optional) Create and activate a virtual environment:
   python3 -m venv venv
   source venv/bin/activate

# Install dependencies:
   pip install -r requirements.txt 
```
## Running Ephor

**To run Ephor directly as a Python script:**

- Open Terminal and navigate to the project directory:
    ```
    cd /path/to/ephor
    ```
- Run the script with:
    ```
    python3 ephor.py
    ```
Note:
Make sure you grant Accessibility permissions (via System Preferences → Security & Privacy → Privacy → Accessibility) to your Terminal or Python interpreter so that Ephor can capture global paste events.

## Building a Standalone Executable

You can build a standalone executable using PyInstaller so that you can run Ephor without invoking the Python interpreter.

- Install PyInstaller (if not already installed):
    ```
    pip install pyinstaller
    ```
- Build the Executable:
    In the project directory, run:
    ```
    pyinstaller --onefile --add-data "rules:rules" ephor.py
    ```
- Test the Executable:
    After the build completes, navigate to the `dist` folder:
    ```
    cd dist
    ./ephor
    ```
## License

This project is licensed under the Apache 2.0 License. See LICENSE for details.


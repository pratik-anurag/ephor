#!/usr/bin/env python3
"""
Ephor - Clipboard Security Agent

- Listens for global paste events (CMD+V) using Quartz event taps.
- When a paste event occurs, reads the clipboard text.
- Scans the text for secrets using regex rules loaded from YAML rule files.
- If a secret is found and the active application is a browser, a warning popup is displayed.
  The popup shows which rule was violated and lets the user either clear the clipboard or continue pasting.

Grant Accessibility permissions to the Python interpreter if you encounter issues with capturing global key events.
"""

import threading
import queue
import time
import subprocess
import re
import pyperclip
import os
import yaml
import logging

# Import macOS APIs.
from AppKit import NSWorkspace
import Quartz

# --- Logging Configuration ---
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

# --- Configuration ---
BROWSER_NAMES = ["Safari", "Google Chrome", "Firefox", "Opera", "Brave Browser"]
import sys
import os

if getattr(sys, 'frozen', False):
    # Running in a PyInstaller bundle
    base_path = sys._MEIPASS
else:
    base_path = os.path.dirname(__file__)

RULES_DIR = os.path.join(base_path, "rules")
paste_event_queue = queue.Queue()


# --- Load and Compile Rules ---
def load_rules(directory):
    """
    Loads and compiles regex rules from YAML files in the given directory.
    Each YAML file should have a top-level key "rules" containing a list of rule objects.
    Each rule object must have a "pattern" key holding the regex pattern.
    
    Returns:
        A list of dictionaries with keys:
          - "name": rule name,
          - "pattern": compiled main regex.
    """
    logging.info(f"Reading rules from {directory}")
    compiled_rules = []
    if not os.path.isdir(directory):
        logging.error(f"Rules directory '{directory}' not found. No rules loaded.")
        return compiled_rules

    for filename in os.listdir(directory):
        if filename.endswith((".yaml", ".yml")):
            full_path = os.path.join(directory, filename)
            try:
                with open(full_path, 'r') as f:
                    rule_data = yaml.safe_load(f)
                    if not rule_data:
                        continue
                    # Check if file has a "rules" list.
                    if "rules" in rule_data and isinstance(rule_data["rules"], list):
                        for rule in rule_data["rules"]:
                            if "pattern" in rule:
                                pattern = " ".join(rule["pattern"].strip().splitlines())
                                try:
                                    compiled = re.compile(pattern)
                                    rule_name = rule.get("name", "Unnamed")
                                    compiled_rules.append({
                                        "name": rule_name,
                                        "pattern": compiled
                                    })
                                except Exception as e:
                                    rule_name = rule.get("name", "Unnamed")
                                    logging.error(f"Failed to compile regex for rule '{rule_name}' in {filename}: {e}")
                    else:
                        # Fallback if the file itself is a single rule.
                        if "pattern" in rule_data:
                            pattern = " ".join(rule_data["pattern"].strip().splitlines())
                            try:
                                compiled = re.compile(pattern)
                                rule_name = rule_data.get("name", "Unnamed")
                                compiled_rules.append({
                                    "name": rule_name,
                                    "pattern": compiled
                                })
                            except Exception as e:
                                logging.error(f"Failed to compile regex from {filename}: {e}")
            except Exception as e:
                logging.error(f"Error loading rule from {filename}: {e}")
    logging.info(f"Loaded {len(compiled_rules)} regex rules from '{directory}'.")
    return compiled_rules

# Pre-load and compile rules.
compiled_rules = load_rules(RULES_DIR)


# --- Secret Scanning ---
def scan_for_secrets(text):
    """
    Scans the given text using all compiled regex rules.
    
    Returns:
        The name of the first rule that matches, or None if no match is found.
    """
    logging.debug("Scanning text for secrets...")
    for rule in compiled_rules:
        if rule["pattern"].search(text):
            logging.debug(f"Matched main pattern of rule: {rule['name']}")
            return rule["name"]
    return None


# --- Notification ---
def warn_user(rule_name):
    """
    Displays a popup dialog using AppleScript. The dialog indicates which rule was violated and
    provides two buttons:
      - "Clear Clipboard" to clear the clipboard.
      - "Continue" to leave the clipboard unchanged.
    
    Args:
        rule_name (str): The name of the violated rule.
    """
    message = (
        f"Sensitive data detected (violated rule: {rule_name}).\n"
        "Press 'Clear Clipboard' to clear the clipboard, or 'Continue' to proceed with pasting."
    )
    script = f'''tell application "System Events"
    set dialogResult to display dialog "{message}" with title "Security Alert" buttons {{"Clear Clipboard", "Continue"}} default button "Clear Clipboard"
    return button returned of dialogResult
end tell'''
    try:
        result = subprocess.check_output(["osascript", "-e", script]).strip().decode("utf-8")
        if result == "Clear Clipboard":
            subprocess.call(["osascript", "-e", 'set the clipboard to ""'])
            logging.info("Clipboard cleared by user.")
        else:
            logging.info("User chose to continue pasting.")
    except Exception as e:
        logging.error(f"Failed to display popup dialog: {e}")


# --- Active Application Detection ---
def get_active_app_name():
    """
    Returns the localized name of the active (frontmost) application.
    """
    active_app = NSWorkspace.sharedWorkspace().frontmostApplication()
    return active_app.localizedName() if active_app else ""


# --- Paste Event Worker ---
def paste_event_worker():
    """
    Worker thread that waits for paste events, reads the clipboard, scans it for secrets,
    and displays a warning if sensitive data is pasted in a recognized browser.
    """
    while True:
        paste_event_queue.get()
        time.sleep(0.05)  # Allow clipboard to update.
        clipboard_text = pyperclip.paste()
        logging.debug(f"Clipboard text: {repr(clipboard_text)}")
        if clipboard_text:
            violated_rule = scan_for_secrets(clipboard_text)
            if violated_rule:
                active_app = get_active_app_name()
                logging.debug(f"Sensitive data detected in active app: {active_app}")
                if any(browser in active_app for browser in BROWSER_NAMES):
                    logging.info(f"Sensitive paste detected (violated rule: {violated_rule}).")
                    warn_user(violated_rule)
                else:
                    logging.info("Sensitive data on clipboard, but active app is not a recognized browser.")
            else:
                logging.debug("No sensitive data found in clipboard.")
        else:
            logging.debug("Clipboard is empty after paste event.")
        paste_event_queue.task_done()


# --- Global Event Tap Callback ---
def event_tap_callback(proxy, event_type, event, refcon):
    """
    Quartz event tap callback to intercept key-down events.
    If CMD+V (keycode 9) is detected, signals the paste event worker.
    """
    if event_type == Quartz.kCGEventKeyDown:
        keycode = Quartz.CGEventGetIntegerValueField(event, Quartz.kCGKeyboardEventKeycode)
        flags = Quartz.CGEventGetFlags(event)
        if flags & Quartz.kCGEventFlagMaskCommand:
            if keycode == 9:  # 'v' key on US QWERTY
                paste_event_queue.put(1)
    return event

# --- Start the Global Event Tap ---
def start_event_tap():
    """
    Creates and starts the Quartz event tap for capturing key-down events.
    """
    event_mask = Quartz.CGEventMaskBit(Quartz.kCGEventKeyDown)
    tap = Quartz.CGEventTapCreate(
        Quartz.kCGSessionEventTap,
        Quartz.kCGHeadInsertEventTap,
        Quartz.kCGEventTapOptionDefault,
        event_mask,
        event_tap_callback,
        None
    )
    if not tap:
        logging.error("Failed to create event tap. Ensure Accessibility permissions are granted.")
        exit(1)
    run_loop_source = Quartz.CFMachPortCreateRunLoopSource(None, tap, 0)
    loop = Quartz.CFRunLoopGetCurrent()
    Quartz.CFRunLoopAddSource(loop, run_loop_source, Quartz.kCFRunLoopDefaultMode)
    Quartz.CGEventTapEnable(tap, True)
    logging.info("Global event tap started. Listening for paste events (CMD+V)...")
    Quartz.CFRunLoopRun()

# --- Main ---
def main():
    """
    Entry point. Starts the paste event worker thread and then the global event tap.
    """
    worker_thread = threading.Thread(target=paste_event_worker, daemon=True)
    worker_thread.start()
    logging.info("Ephor - Clipboard Security Agent started. Monitoring paste events...")
    start_event_tap()

if __name__ == "__main__":
    main()

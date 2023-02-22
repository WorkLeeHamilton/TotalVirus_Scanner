import hashlib
import os
import requests
import subprocess
import time
import tkinter as tk
from tkinter import filedialog

# Define the API endpoint and parameters
url = "https://www.virustotal.com/vtapi/v2/file/report"
params = {"apikey": "YOUR_API_KEY", "resource": ""}


def get_file_hash(file_path):
    """
    Get the SHA-256 hash of a file.
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except IOError as e:
        print(f"Error while hashing {file_path}: {e}")
        return None


def scan_file(file_path, report_file):
    """
    Scan a file for known threats using VirusTotal.
    """
    file_hash = get_file_hash(file_path)
    if file_hash:
        params["resource"] = file_hash
        response = requests.get(url, params=params)
        if response.status_code == 200:
            json_response = response.json()
            if json_response["response_code"] == 0:
                report_file.write(f"{file_path}: No known threats detected\n")
            elif json_response["response_code"] == 1:
                positives = json_response["positives"]
                total = json_response["total"]
                report_file.write(f"{file_path}: {positives}/{total} engines detected a threat\n")
            else:
                report_file.write(f"{file_path}: Error - {json_response['verbose_msg']}\n")
        else:
            report_file.write(f"{file_path}: Error - {response.status_code}\n")
    time.sleep(1)  # Wait for 1 second before scanning the next file


def scan_folder(folder_path):
    """
    Scan all files in a folder for known threats using VirusTotal.
    """
    with open("virus_scan_report.txt", "w") as report_file:
        for root, dirs, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                scan_file(file_path, report_file)
    subprocess.run(["notepad.exe", "virus_scan_report.txt"])


def get_api_key():
    """
    Display a GUI for entering the VirusTotal API key.
    """
    def submit():
        global api_key
        api_key = api_key_entry.get()
        window.destroy()

    window = tk.Tk()
    window.title("Threat Hunter")
    window.geometry("400x200")  # Set the dimensions of the window
    api_key_label = tk.Label(window, text="Enter your VirusTotal API key:")
    api_key_label.pack()
    api_key_entry = tk.Entry(window, width=50)
    api_key_entry.pack(pady=10)
    next_button = tk.Button(window, text="Scan Folder", command=submit)
    next_button.pack()
    # Center the window on the screen
    window.update_idletasks()
    screen_width = window.winfo_screenwidth()
    screen_height = window.winfo_screenheight()
    window_width = window.winfo_width()
    window_height = window.winfo_height()
    x = int((screen_width - window_width) / 2)
    y = int((screen_height - window_height) / 2)
    window.geometry(f"+{x}+{y}")
    window.mainloop()


if __name__ == "__main__":
    get_api_key()
    params["apikey"] = api_key

    root = tk.Tk()
    root.withdraw()
    folder_path = filedialog.askdirectory(title="Select Folder")
    if folder_path:
        scan_folder(folder_path)
    else:
        print("No folder selected.")

import time
import requests
import asyncio
import aiohttp
import shutil
import hashlib
import datetime
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

DEEPSEEK_API_URL = "http://127.0.0.1:1234"
SUSPICIOUS_EXTENSIONS = [".locked", ".encrypted", ".enc", ".crypt", ".crypted", ".cryp1"]

BACKUP_ROOT = "rfp_backups"  

class RansomwareHandler(FileSystemEventHandler):
    def __init__(self, folder, log_func, record_event_func, ai_mode):
        self.folder = folder
        self.log = log_func
        self.record_event = record_event_func
        self.ai_mode = ai_mode
        self.safe_file_hashes = {}  # Store known safe file hashes
        safe_folder_name = folder.replace(":", "").replace("\\", "_").replace("/", "_")
        self.backup_dir = os.path.join(BACKUP_ROOT, safe_folder_name)
        os.makedirs(self.backup_dir, exist_ok=True)

    def calculate_hash(self, file_path):
        try:
            hasher = hashlib.md5()
            with open(file_path, 'rb') as f:
                buf = f.read()
                hasher.update(buf)
            return hasher.hexdigest()
        except Exception:
            return None

    def backup_file(self, file_path):
        try:
            filename = os.path.basename(file_path)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_name = f"{timestamp}_{filename}"
            backup_path = os.path.join(self.backup_dir, backup_name)
            shutil.copy2(file_path, backup_path)
            self.log(f"[BACKUP] 🛡️ File backed up: {file_path} → {backup_path}")
        except Exception as e:
            self.log(f"[ERROR] ❌ Backup failed for {file_path}: {e}")

    def on_modified(self, event):
        if not event.is_directory:
            self.analyze_file(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.analyze_file(event.src_path)

    def analyze_file(self, file_path):
        if self.ai_mode:
            asyncio.run(self.analyze_file_async(file_path))
        else:
            self.analyze_file_sync(file_path)

    def analyze_file_sync(self, file_path):
        normalized_path = os.path.normpath(file_path)
        backup_dir_norm = os.path.normpath(self.backup_dir)

        if normalized_path.startswith(backup_dir_norm):
            return

        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        is_suspicious = self.is_suspicious(file_path)
        ai_result = None

        current_hash = self.calculate_hash(file_path)
        old_hash = self.safe_file_hashes.get(file_path)

        if old_hash and current_hash and old_hash != current_hash and is_suspicious:
            self.backup_file(file_path)
        elif is_suspicious and current_hash and file_path not in self.safe_file_hashes:
            self.backup_file(file_path)

        if not is_suspicious and current_hash:
            if old_hash is None or current_hash != old_hash:
                self.backup_file(file_path)
        self.safe_file_hashes[file_path] = current_hash

        if is_suspicious:
            self.log(f"[ALERT] 🚨 Suspicious encrypted file detected: {file_path}")
        else:
            self.log(f"[INFO] ℹ️ File changed: {file_path}")

        self.record_event({
            "timestamp": timestamp,
            "folder": self.folder,
            "file": file_path,
            "ai_mode": self.ai_mode,
            "suspicious": is_suspicious,
            "ai_result": ai_result
        })

    async def analyze_file_async(self, file_path):
        normalized_path = os.path.normpath(file_path)
        backup_dir_norm = os.path.normpath(self.backup_dir)

        if normalized_path.startswith(backup_dir_norm):
            return

        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        is_suspicious = self.is_suspicious(file_path)
        ai_result = None

        current_hash = self.calculate_hash(file_path)
        old_hash = self.safe_file_hashes.get(file_path)

        if old_hash and current_hash and old_hash != current_hash and is_suspicious:
            self.backup_file(file_path)
        elif is_suspicious and current_hash and file_path not in self.safe_file_hashes:
            self.backup_file(file_path)

        if not is_suspicious and current_hash:
            if old_hash is None or current_hash != old_hash:
                self.backup_file(file_path)
            self.safe_file_hashes[file_path] = current_hash

        if is_suspicious:
            self.log(f"[ALERT] 🚨 Suspicious encrypted file detected: {file_path}")
        else:
            self.log(f"[INFO] ℹ️ File changed: {file_path}")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{DEEPSEEK_API_URL}/v1/completions",
                    headers={"Content-Type": "application/json"},
                    json={
                        "model": "deepseek-r1-distill-llama-8b",
                        "prompt": f"Is this file showing ransomware-like activity? Reply YES or NO with a short reason in one sentence only: {file_path}",
                        "max_tokens": 200,
                        "temperature": 0.5
                    }
                ) as response:
                    result = await response.json()
                    choices = result.get("choices")
                    if choices and len(choices) > 0:
                        ai_result = choices[0].get("text", "No AI response.")
                    else:
                        ai_result = "No AI response."
                    self.log(f"[AI ANALYSIS] 🔍 Deep ransomware check on: {file_path}\nResult: {ai_result}")
        except Exception as e:
            ai_result = f"AI error: {e}"
            self.log(f"[AI ERROR] ❌ DeepSeek failed: {e}")

        self.record_event({
            "timestamp": timestamp,
            "folder": self.folder,
            "file": file_path,
            "ai_mode": self.ai_mode,
            "suspicious": is_suspicious,
            "ai_result": ai_result
        })

    def is_suspicious(self, file_path):
        return any(file_path.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)

class MonitorManager:
    def __init__(self):
        self.folders = []
        self.observer = None
        self.handlers = []
        self.activity_log = []
        self.event_records = []
        self.decrypted_files = []
        self.running = False

    def add_decrypted_file(self, filename, folder, timestamp):
        self.decrypted_files.insert(0, {
            "filename": filename,
            "folder": folder,
            "timestamp": timestamp
        })
        self.decrypted_files = self.decrypted_files[:5]  

    def log(self, message):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        full_msg = f"{timestamp} - {message}"
        self.activity_log.append(full_msg)
        print(full_msg)

    def record_event(self, event_data):
        self.event_records.append(event_data)

    def get_event_data(self):
        return self.event_records

    def add_folder(self, folder_path):
        abs_path = os.path.abspath(folder_path)
        if abs_path not in self.folders:
            self.folders.append(abs_path)
            self.log(f"📁 Folder added: {abs_path}")

    def remove_folder(self, folder_path):
        abs_path = os.path.abspath(folder_path)
        if abs_path in self.folders:
            self.folders.remove(abs_path)
            self.log(f"❌ Folder removed: {abs_path}")
            self.event_records = [e for e in self.event_records if e["folder"] != abs_path]


    def get_monitored_folders(self):
        return self.folders

    def start_monitoring(self, ai_mode):
        if self.running:
            return

        self.observer = Observer()

        for folder in self.folders:
            self.log(f"🔍 Starting monitoring for: {folder}")

            handler = RansomwareHandler(folder, self.log, self.record_event, ai_mode)
            self.handlers.append(handler)
            self.observer.schedule(handler, folder, recursive=True)

            for root, _, files in os.walk(folder):
                for file in files:
                    path = os.path.join(root, file)
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
                    is_suspicious = any(file.lower().endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
                    result = None

                    if is_suspicious:
                        self.log(f"🔒 Suspicious file found: {path}")
                    else:
                        self.log(f"✅ Safe file found: {path}")
                        file_hash = handler.calculate_hash(path)
                        if file_hash:
                            previous = handler.safe_file_hashes.get(path)
                            if not previous or file_hash != previous:
                                handler.safe_file_hashes[path] = file_hash
                                handler.backup_file(path)

                    if ai_mode:
                        try:
                            response = requests.post(
                                f"{DEEPSEEK_API_URL}/v1/completions",
                                headers={"Content-Type": "application/json"},
                                json={
                                    "model": "deepseek-r1-distill-llama-8b",
                                    "prompt": f"Is '{os.path.basename(path)}' likely ransomware? Return YES/NO and short reason.",
                                    "max_tokens": 100,
                                    "temperature": 0.5
                                }
                            )
                            result_json = response.json()
                            choices = result_json.get("choices")
                            if choices and len(choices) > 0:
                                result = choices[0].get("text", "No AI response.")
                            else:
                                result = "No AI response."

                            if is_suspicious:
                                self.log(f"        🔍 [AI Result]: {result}")
                        except Exception as e:
                            result = f"AI error: {e}"
                            if is_suspicious:
                                self.log(f"        ❌ [AI ERROR]: {e}")

                    self.record_event({
                        "timestamp": timestamp,
                        "folder": folder,
                        "file": path,
                        "ai_mode": ai_mode,
                        "suspicious": is_suspicious,
                        "ai_result": result
                    })

        self.observer.start()
        self.running = True
        self.log("🚀 Real-time monitoring started.")

    def stop_monitoring(self):
        if self.observer and self.running:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            self.handlers.clear()
            self.running = False
            self.log("⏹ Monitoring stopped.")

from flask import Flask, render_template, request, redirect, url_for, send_file, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user, UserMixin
from monitor import MonitorManager
from decryptor import decrypt_file as rsa_decrypt_file
import datetime
import os
import zipfile
import io
from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.secret_key = 'your-secret-key'

app.config['SESSION_PERMANENT'] = False

monitor_manager = MonitorManager()
AI_MODE = False
selected_folder = None  # Stores last added folder for decrypt form

# --- Flask-Login setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# --- Dummy user class ---
class User(UserMixin):
    def __init__(self, id):
        self.id = id

# --- Load user for Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Hardcoded credentials for demo purposes
    VALID_USERNAME = os.getenv('RFP_USERNAME')
    VALID_PASSWORD = os.getenv('RFP_PASSWORD')

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username == VALID_USERNAME and password == VALID_PASSWORD:
            user = User(username)
            login_user(user)
            return redirect(url_for('index'))
        else:
            return "❌ Invalid username or password. Please try again."

    return render_template('login.html')

@app.route('/')
@login_required
def index():
    # Get list of encrypted files from monitored folders
    monitored_files = []
    for folder in monitor_manager.get_monitored_folders():
        try:
            for filename in os.listdir(folder):
                if filename.endswith('.enc'):
                    monitored_files.append(os.path.join(folder, filename))
        except Exception:
            continue  

    return render_template('index.html',
        folders=monitor_manager.get_monitored_folders(),
        logs=monitor_manager.activity_log,
        ai_mode=AI_MODE,
        now=datetime.datetime.now(),
        selected_folder=selected_folder,
        monitored_files=monitored_files,
        monitor_manager=monitor_manager  # Make sure this is passed
    )

@app.route('/add_folder', methods=['POST'])
@login_required
def add_folder():
    global selected_folder
    folder_path = request.form.get('folder_path')
    if folder_path:
        monitor_manager.add_folder(folder_path)
        selected_folder = folder_path  # Store for decryption form
    return redirect(url_for('index'))

@app.route('/delete_folder/<path:folder_path>', methods=['POST'])
@login_required
def delete_folder(folder_path):
    monitor_manager.remove_folder(folder_path)
    return redirect(url_for('index'))

@app.route('/start_monitoring', methods=['POST'])
@login_required
def start_monitoring():
    global AI_MODE
    AI_MODE = request.form.get('ai_mode') == 'on'
    monitor_manager.start_monitoring(AI_MODE)
    return redirect(url_for('index'))

@app.route('/stop_monitoring', methods=['POST'])
@login_required
def stop_monitoring():
    monitor_manager.stop_monitoring()
    return redirect(url_for('index'))

@app.route('/toggle_ai', methods=['POST'])
@login_required
def toggle_ai():
    global AI_MODE
    AI_MODE = not AI_MODE
    return redirect(url_for('index'))

@app.route('/clear-log', methods=['POST'])
@login_required
def clear_log():
    monitor_manager.activity_log.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    folder_filter = request.args.get('folder', '')

    filtered_events = []
    for event in monitor_manager.get_event_data():
        if folder_filter and event['folder'] != folder_filter:
            continue

        filtered_events.append(event)

    total_suspicious = 0
    total_safe = 0
    for event in filtered_events:
        if event['suspicious']:
            total_suspicious += 1
        else:
            total_safe += 1

    chart_data = {
        "labels": ["Suspicious Files", "Safe Files"],
        "suspicious": [total_suspicious],
        "safe": [total_safe]
    }
    # Calculate most targeted folder
    from collections import Counter

    suspicious_folder_counts = Counter()
    for event in filtered_events:
        if event['suspicious']:
            suspicious_folder_counts[event['folder']] += 1

    most_targeted_folder = None
    if suspicious_folder_counts:
        most_targeted_folder = suspicious_folder_counts.most_common(1)[0]  # (folder, count)

    return render_template("dashboard.html",
                       folders=monitor_manager.get_monitored_folders(),
                       chart_data=chart_data,
                       selected_folder=folder_filter,
                       most_targeted_folder=most_targeted_folder,
                       monitor_manager=monitor_manager,
                       recent_decrypted_files = monitor_manager.decrypted_files)

@app.route('/decrypt_file', methods=['POST'])
@login_required
def decrypt_file_route():
    encrypted_file_path = request.form.get("encrypted_file_path")
    folder = request.form.get("selected_folder")

    if not encrypted_file_path or not os.path.exists(encrypted_file_path):
        return "❌ File not found."

    try:
        with open(encrypted_file_path, "rb") as f:
            data = f.read()
        decrypted_path = rsa_decrypt_file(data, os.path.basename(encrypted_file_path), output_dir=folder)
        filename_only = os.path.basename(decrypted_path)
        message = f"✅ File '{filename_only}' was successfully decrypted and saved to: {folder}"
        monitor_manager.add_decrypted_file(
            filename_only,
            folder,
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
        flash(message, "success")
        return redirect(url_for('index'))
    except Exception as e:
        return f"❌ Error: {str(e)}"
    
@app.route('/download_logs', methods=['GET', 'POST'])
@login_required
def download_logs():
    if request.method == 'POST':
        include_activity = 'activity_log' in request.form
        include_folders = 'monitored_folders' in request.form
        include_decryption = 'decryption_log' in request.form

        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w') as zipf:
            if include_activity:
                activity_log = "\n".join(monitor_manager.activity_log)
                zipf.writestr("activity_log.txt", activity_log)

            if include_folders:
                monitored_folders = "\n".join(monitor_manager.get_monitored_folders())
                zipf.writestr("monitored_folders.txt", monitored_folders)

            if include_decryption and os.path.exists("decryption_log.json"):
                with open("decryption_log.json", "r") as f:
                    zipf.writestr("decryption_log.json", f.read())

        memory_file.seek(0)

        # Generate filename with today's date
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        filename = f"ransomware_logs_{today}.zip"

        return send_file(memory_file, as_attachment=True, download_name=filename)

    # GET request: show selection form
    return render_template("download_logs.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)

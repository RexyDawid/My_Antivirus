import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import yara
import os
import shutil
import threading

# --- YARA Regeln laden ---
RULE_PATH = "rules.yar"  # Pfad zur Regeldatei anpassen!
try:
    rules = yara.compile(filepath=RULE_PATH)
except Exception as e:
    rules = None
    print(f"Fehler beim Laden der YARA Regeln: {e}")

# --- Funktionen ---
def scan_file(filepath):
    try:
        return rules.match(filepath) if rules else []
    except Exception:
        return []

def move_folder_to_quarantine(folderpath):
    quarantine_dir = "Quarantine"
    os.makedirs(quarantine_dir, exist_ok=True)
    dest = os.path.join(quarantine_dir, os.path.basename(folderpath))
    try:
        if os.path.exists(dest):
            i = 1
            while os.path.exists(dest + f"_{i}"):
                i += 1
            dest = dest + f"_{i}"
        shutil.move(folderpath, dest)
    except Exception as e:
        print(f"Verschieben des Ordners fehlgeschlagen: {e}")

def scan_path(path, update_status, log_append, stop_event):
    infected = []
    files_scanned = 0
    for root, _, files in os.walk(path):
        for file in files:
            if stop_event.is_set():
                update_status("Scan abgebrochen!")
                return infected
            fp = os.path.join(root, file)
            update_status(f"Scanne: {fp}")
            log_append(f"Scanne Datei: {fp}")
            if scan_file(fp):
                infected.append(fp)
                folder_to_move = os.path.dirname(fp)
                move_folder_to_quarantine(folder_to_move)
                log_append(f"!!! Gefährlich: {fp} -> Ordner {folder_to_move} in Quarantäne")
                # Ordner verschoben, daher keine weiteren Dateien aus diesem Ordner scannen
                break
            files_scanned += 1
    update_status(f"Scan fertig! {files_scanned} Dateien geprüft.")
    return infected

# --- GUI Setup ---
class AntivirusGUI:
    def __init__(self, root):
        self.root = root
        root.title("Antivirus Scanner")
        root.geometry("720x520")
        root.configure(bg="#121212")

        self.stop_event = threading.Event()
        self.selected_folder = None
        self.selected_file = None

        self.status_var = tk.StringVar(value="Bereit")

        self.create_widgets()

    def create_widgets(self):
        # Status Label (oben, klarer grün)
        self.status_label = tk.Label(self.root, textvariable=self.status_var, fg="#32CD32", bg="#121212", font=("Consolas", 14, "bold"))
        self.status_label.pack(pady=(15,10))

        # Scan Mode Selector
        frame_modes = tk.Frame(self.root, bg="#121212")
        frame_modes.pack(pady=(0,15))
        tk.Label(frame_modes, text="Scan-Modus:", fg="#CCCCCC", bg="#121212", font=("Consolas", 13)).pack(side="left")

        self.scan_mode = ttk.Combobox(frame_modes, values=["Full Scan", "Quick Scan", "Custom Folder Scan", "Single File Scan"], state="readonly", width=22, font=("Consolas", 12))
        self.scan_mode.current(0)
        self.scan_mode.pack(side="left", padx=12)

        # Folder and File select buttons (etwas größer, mit Hover-Farbe)
        frame_select = tk.Frame(self.root, bg="#121212")
        frame_select.pack(pady=(0,20))

        btn_style = {"bg": "#333", "fg": "#EEE", "font": ("Consolas", 11, "bold"), "relief": "flat", "activebackground": "#444", "activeforeground": "#FFF", "width": 15, "cursor": "hand2"}

        self.btn_select_folder = tk.Button(frame_select, text="Ordner auswählen", command=self.select_folder, **btn_style)
        self.btn_select_folder.pack(side="left", padx=15)

        self.btn_select_file = tk.Button(frame_select, text="Datei auswählen", command=self.select_file, **btn_style)
        self.btn_select_file.pack(side="left", padx=15)

        # Buttons Frame (Start/Stop)
        frame_buttons = tk.Frame(self.root, bg="#121212")
        frame_buttons.pack(pady=(0,25))

        scan_btn_style = {"bg": "#2E8B57", "fg": "#FFF", "font": ("Consolas", 14, "bold"), "relief": "flat", "activebackground": "#3CB371", "activeforeground": "#FFF", "width": 12, "cursor": "hand2"}
        stop_btn_style = {"bg": "#B22222", "fg": "#FFF", "font": ("Consolas", 14, "bold"), "relief": "flat", "activebackground": "#CD5C5C", "activeforeground": "#FFF", "width": 12, "cursor": "hand2"}

        self.scan_button = tk.Button(frame_buttons, text="Scan starten", command=self.start_scan, **scan_btn_style)
        self.scan_button.pack(side="left", padx=25)

        self.stop_button = tk.Button(frame_buttons, text="Scan stoppen", command=self.stop_scan, **stop_btn_style, state="disabled")
        self.stop_button.pack(side="left", padx=25)

        # Log Textfeld (mit Rahmen und abgerundeten Ecken via Frame)
        log_frame = tk.Frame(self.root, bg="#1C1C1C", bd=2, relief="sunken")
        log_frame.pack(pady=(0, 20), padx=15, fill="both", expand=True)

        self.log = tk.Text(log_frame, bg="#000000", fg="#32CD32", font=("Consolas", 11), state="disabled", wrap="word", bd=0, insertbackground="#32CD32", height=15)
        self.log.pack(fill="both", expand=True)

        # Info Label (unten)
        self.info_label = tk.Label(self.root, text="", fg="#AAA", bg="#121212", font=("Consolas", 11, "italic"))
        self.info_label.pack(pady=(0,15))

    def select_folder(self):
        folder = filedialog.askdirectory(title="Ordner auswählen")
        if folder:
            self.selected_folder = folder
            self.selected_file = None
            self.info_label.config(text=f"Gewählter Ordner: {folder}")

    def select_file(self):
        file = filedialog.askopenfilename(title="Datei auswählen")
        if file:
            self.selected_file = file
            self.selected_folder = None
            self.info_label.config(text=f"Gewählte Datei: {file}")

    def log_append(self, msg):
        self.log.config(state="normal")
        self.log.insert(tk.END, msg + "\n")
        self.log.see(tk.END)
        self.log.config(state="disabled")

    def update_status(self, msg):
        self.status_var.set(msg)
        self.root.update_idletasks()

    def start_scan(self):
        mode = self.scan_mode.get()
        self.stop_event.clear()

        # Auswahl prüfen
        if mode == "Custom Folder Scan":
            if not self.selected_folder:
                messagebox.showwarning("Warnung", "Bitte zuerst einen Ordner auswählen!")
                return
            target = self.selected_folder

        elif mode == "Single File Scan":
            if not self.selected_file:
                messagebox.showwarning("Warnung", "Bitte zuerst eine Datei auswählen!")
                return
            target = self.selected_file

        elif mode == "Full Scan":
            target = os.path.expanduser("~")

        elif mode == "Quick Scan":
            desktop = os.path.join(os.path.expanduser("~"), "Desktop")
            downloads = os.path.join(os.path.expanduser("~"), "Downloads")
            target = [p for p in (desktop, downloads) if os.path.exists(p)]

        else:
            messagebox.showerror("Fehler", "Unbekannter Scan-Modus!")
            return

        self.scan_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.log_append(f"Starte {mode}...")

        def scan_thread():
            if isinstance(target, list):
                total_infected = []
                for t in target:
                    if self.stop_event.is_set():
                        break
                    infected = scan_path(t, self.update_status, self.log_append, self.stop_event)
                    total_infected.extend(infected)
            elif isinstance(target, str) and os.path.isfile(target):
                infected = []
                self.update_status(f"Scanne Datei: {target}")
                self.log_append(f"Scanne Datei: {target}")
                if scan_file(target):
                    infected.append(target)
                    folder_to_move = os.path.dirname(target)
                    move_folder_to_quarantine(folder_to_move)
                    self.log_append(f"!!! Gefährlich: {target} -> Ordner {folder_to_move} in Quarantäne")
                total_infected = infected
            else:
                total_infected = scan_path(target, self.update_status, self.log_append, self.stop_event)

            if total_infected and not self.stop_event.is_set():
                messagebox.showwarning("Scan Ergebnis", f"{len(total_infected)} Bedrohungen gefunden! Dateien/Ordner in Quarantäne verschoben.")
            elif not self.stop_event.is_set():
                messagebox.showinfo("Scan Ergebnis", "Keine Bedrohungen gefunden!")

            self.update_status("Bereit")
            self.scan_button.config(state="normal")
            self.stop_button.config(state="disabled")

        threading.Thread(target=scan_thread, daemon=True).start()

    def stop_scan(self):
        self.stop_event.set()
        self.update_status("Scan wird gestoppt...")

def main():
    root = tk.Tk()
    app = AntivirusGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

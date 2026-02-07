import json
import os
import base64
import secrets
import string
import threading
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vault.dat")
SALT_SIZE = 16
CLIPBOARD_CLEAR_SECONDS = 15


def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))


def load_vault(master_password: str) -> list[dict]:
    with open(VAULT_FILE, "rb") as f:
        data = f.read()
    salt = data[:SALT_SIZE]
    encrypted = data[SALT_SIZE:]
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted)
    return json.loads(decrypted)


def save_vault(master_password: str, entries: list[dict], salt: bytes | None = None):
    if salt is None:
        if os.path.exists(VAULT_FILE):
            with open(VAULT_FILE, "rb") as f:
                salt = f.read(SALT_SIZE)
        else:
            salt = os.urandom(SALT_SIZE)
    key = derive_key(master_password, salt)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(json.dumps(entries).encode())
    with open(VAULT_FILE, "wb") as f:
        f.write(salt + encrypted)


def generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + string.punctuation
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c in string.ascii_lowercase for c in pw)
            and any(c in string.ascii_uppercase for c in pw)
            and any(c in string.digits for c in pw)
            and any(c in string.punctuation for c in pw)
        ):
            return pw


class PasswordManagerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("600x450")
        self.root.minsize(500, 350)

        self.master_password: str = ""
        self.entries: list[dict] = []
        self.clipboard_timer: threading.Timer | None = None

        self._show_login_screen()

    # ── Login / Setup Screen ──────────────────────────────────────

    def _show_login_screen(self):
        self._clear_root()

        frame = ttk.Frame(self.root, padding=30)
        frame.place(relx=0.5, rely=0.5, anchor="center")

        first_run = not os.path.exists(VAULT_FILE)

        if first_run:
            ttk.Label(frame, text="Create Master Password", font=("Segoe UI", 14, "bold")).grid(
                row=0, column=0, columnspan=2, pady=(0, 15)
            )
        else:
            ttk.Label(frame, text="Unlock Vault", font=("Segoe UI", 14, "bold")).grid(
                row=0, column=0, columnspan=2, pady=(0, 15)
            )

        ttk.Label(frame, text="Master Password:").grid(row=1, column=0, sticky="e", padx=(0, 8))
        self.pw_entry = ttk.Entry(frame, show="*", width=30)
        self.pw_entry.grid(row=1, column=1)
        self.pw_entry.focus()

        if first_run:
            ttk.Label(frame, text="Confirm Password:").grid(row=2, column=0, sticky="e", padx=(0, 8), pady=(8, 0))
            self.pw_confirm = ttk.Entry(frame, show="*", width=30)
            self.pw_confirm.grid(row=2, column=1, pady=(8, 0))
            btn_text = "Create"
        else:
            self.pw_confirm = None
            btn_text = "Unlock"

        btn = ttk.Button(frame, text=btn_text, command=self._on_login)
        btn.grid(row=3, column=0, columnspan=2, pady=(18, 0))

        self.root.bind("<Return>", lambda e: self._on_login())

    def _on_login(self):
        password = self.pw_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Password cannot be empty.")
            return

        first_run = not os.path.exists(VAULT_FILE)

        if first_run:
            confirm = self.pw_confirm.get()
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match.")
                return
            if len(password) < 4:
                messagebox.showwarning("Warning", "Password should be at least 4 characters.")
                return
            self.master_password = password
            self.entries = []
            salt = os.urandom(SALT_SIZE)
            save_vault(self.master_password, self.entries, salt)
            self._show_main_screen()
        else:
            try:
                self.entries = load_vault(password)
                self.master_password = password
                self._show_main_screen()
            except (InvalidToken, Exception):
                messagebox.showerror("Error", "Incorrect master password.")

    # ── Main Screen ───────────────────────────────────────────────

    def _show_main_screen(self):
        self._clear_root()
        self.root.unbind("<Return>")

        toolbar = ttk.Frame(self.root, padding=(10, 8))
        toolbar.pack(fill="x")

        ttk.Button(toolbar, text="+ Add New", command=self._show_add_dialog).pack(side="left")
        ttk.Button(toolbar, text="Lock", command=self._lock).pack(side="right")

        # Scrollable list
        container = ttk.Frame(self.root)
        container.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        canvas = tk.Canvas(container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        self.list_frame = ttk.Frame(canvas)

        self.list_frame.bind(
            "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=self.list_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Mousewheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        canvas.bind_all("<MouseWheel>", _on_mousewheel)

        self._refresh_entries()

    def _refresh_entries(self):
        for widget in self.list_frame.winfo_children():
            widget.destroy()

        if not self.entries:
            ttk.Label(self.list_frame, text="No saved passwords yet. Click '+ Add New' to get started.",
                      foreground="gray").pack(pady=30)
            return

        for idx, entry in enumerate(self.entries):
            row = ttk.Frame(self.list_frame, padding=(8, 6))
            row.pack(fill="x", pady=2)

            info = ttk.Frame(row)
            info.pack(side="left", fill="x", expand=True)

            ttk.Label(info, text=entry["service"], font=("Segoe UI", 10, "bold")).pack(anchor="w")
            ttk.Label(info, text=entry["username"], foreground="gray").pack(anchor="w")

            btns = ttk.Frame(row)
            btns.pack(side="right")

            ttk.Button(btns, text="Copy", width=6,
                       command=lambda i=idx: self._copy_password(i)).pack(side="left", padx=2)
            ttk.Button(btns, text="Delete", width=6,
                       command=lambda i=idx: self._delete_entry(i)).pack(side="left", padx=2)

            ttk.Separator(self.list_frame, orient="horizontal").pack(fill="x")

    def _copy_password(self, index: int):
        password = self.entries[index]["password"]
        self.root.clipboard_clear()
        self.root.clipboard_append(password)

        if self.clipboard_timer is not None:
            self.clipboard_timer.cancel()

        def clear_clipboard():
            try:
                self.root.clipboard_clear()
            except tk.TclError:
                pass

        self.clipboard_timer = threading.Timer(CLIPBOARD_CLEAR_SECONDS, clear_clipboard)
        self.clipboard_timer.daemon = True
        self.clipboard_timer.start()

        messagebox.showinfo("Copied",
                            f"Password copied to clipboard.\nIt will be cleared in {CLIPBOARD_CLEAR_SECONDS} seconds.")

    def _delete_entry(self, index: int):
        service = self.entries[index]["service"]
        if messagebox.askyesno("Confirm Delete", f"Delete entry for '{service}'?"):
            self.entries.pop(index)
            save_vault(self.master_password, self.entries)
            self._refresh_entries()

    def _lock(self):
        self.master_password = ""
        self.entries = []
        self._show_login_screen()

    # ── Add Entry Dialog ──────────────────────────────────────────

    def _show_add_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Add New Entry")
        dialog.geometry("400x250")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()

        frame = ttk.Frame(dialog, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Service Name:").grid(row=0, column=0, sticky="e", padx=(0, 8), pady=4)
        service_var = tk.StringVar()
        ttk.Entry(frame, textvariable=service_var, width=30).grid(row=0, column=1, columnspan=2, pady=4)

        ttk.Label(frame, text="Username:").grid(row=1, column=0, sticky="e", padx=(0, 8), pady=4)
        username_var = tk.StringVar()
        ttk.Entry(frame, textvariable=username_var, width=30).grid(row=1, column=1, columnspan=2, pady=4)

        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky="e", padx=(0, 8), pady=4)
        password_var = tk.StringVar()
        pw_entry = ttk.Entry(frame, textvariable=password_var, width=22)
        pw_entry.grid(row=2, column=1, pady=4, sticky="w")

        ttk.Button(frame, text="Generate", width=8,
                   command=lambda: password_var.set(generate_password())).grid(row=2, column=2, pady=4, padx=(4, 0))

        def on_save():
            service = service_var.get().strip()
            username = username_var.get().strip()
            password = password_var.get()

            if not service:
                messagebox.showwarning("Warning", "Service name is required.", parent=dialog)
                return
            if not password:
                messagebox.showwarning("Warning", "Password is required.", parent=dialog)
                return

            self.entries.append({
                "service": service,
                "username": username,
                "password": password,
            })
            save_vault(self.master_password, self.entries)
            dialog.destroy()
            self._refresh_entries()

        ttk.Button(frame, text="Save", command=on_save).grid(
            row=3, column=0, columnspan=3, pady=(18, 0)
        )

    # ── Helpers ───────────────────────────────────────────────────

    def _clear_root(self):
        for widget in self.root.winfo_children():
            widget.destroy()


def main():
    root = tk.Tk()
    PasswordManagerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()

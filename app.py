import tkinter as tk
from tkinter import messagebox, ttk
import database as db


class PasswordManagerApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title("Desktop Password Manager")
        self.geometry("620x450")
        self.resizable(False, False)

        db.init_db()
        self.fernet = None

        self.container = tk.Frame(self)
        self.container.pack(fill="both", expand=True)

        if not db.is_master_set():
            self.show_setup_screen()
        else:
            self.show_login_screen()

    def clear_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    # --- Setup Screen (First-time run) ---
    def show_setup_screen(self):
        self.clear_container()
        frame = tk.Frame(self.container, padx=20, pady=20)
        frame.pack(expand=True)

        tk.Label(
            frame, text="Create Master Password", font=("Arial", 14, "bold")
        ).pack(pady=10)
        tk.Label(
            frame,
            text="This password will encrypt and secure your credentials.",
        ).pack(pady=5)

        entry_pw = tk.Entry(frame, show="*", width=30)
        entry_pw.pack(pady=5)

        def handle_setup():
            pw = entry_pw.get().strip()
            if not pw:
                messagebox.showerror("Error", "Password cannot be empty.")
                return
            db.set_master_password(pw)
            messagebox.showinfo("Success", "Master password set! Please log in.")
            self.show_login_screen()

        tk.Button(frame, text="Save Master Password", command=handle_setup).pack(
            pady=10
        )

    # --- Login Screen ---
    def show_login_screen(self):
        self.clear_container()
        frame = tk.Frame(self.container, padx=20, pady=20)
        frame.pack(expand=True)

        tk.Label(frame, text="Unlock Vault", font=("Arial", 14, "bold")).pack(
            pady=10
        )

        entry_pw = tk.Entry(frame, show="*", width=30)
        entry_pw.pack(pady=5)
        entry_pw.focus()

        def handle_login():
            pw = entry_pw.get().strip()
            fernet = db.verify_master_password(pw)
            if fernet:
                self.fernet = fernet
                self.show_vault_screen()
            else:
                messagebox.showerror("Error", "Incorrect master password.")
                entry_pw.delete(0, tk.END)

        self.bind("<Return>", lambda event: handle_login())
        tk.Button(frame, text="Login", command=handle_login, width=15).pack(
            pady=10
        )

    # --- Vault Screen ---
    def show_vault_screen(self):
        self.unbind("<Return>")
        self.clear_container()

        # Top Bar
        top_bar = tk.Frame(self.container, padx=10, pady=10)
        top_bar.pack(fill="x")
        tk.Label(top_bar, text="Saved Logins", font=("Arial", 12, "bold")).pack(
            side="left"
        )
        tk.Button(top_bar, text="Lock Vault", command=self.lock_vault).pack(
            side="right"
        )

        # Input Form
        form_frame = tk.LabelFrame(
            self.container, text="Add New Entry", padx=10, pady=10
        )
        form_frame.pack(fill="x", padx=10, pady=5)

        tk.Label(form_frame, text="Service:").grid(row=0, column=0, padx=5)
        entry_service = tk.Entry(form_frame, width=15)
        entry_service.grid(row=0, column=1, padx=5)

        tk.Label(form_frame, text="Username:").grid(row=0, column=2, padx=5)
        entry_user = tk.Entry(form_frame, width=15)
        entry_user.grid(row=0, column=3, padx=5)

        tk.Label(form_frame, text="Password:").grid(row=0, column=4, padx=5)
        entry_pass = tk.Entry(form_frame, width=15)
        entry_pass.grid(row=0, column=5, padx=5)

        def add_entry():
            s = entry_service.get().strip()
            u = entry_user.get().strip()
            p = entry_pass.get().strip()
            if not s or not u or not p:
                messagebox.showwarning("Warning", "All fields are required.")
                return
            db.add_credential(self.fernet, s, u, p)
            entry_service.delete(0, tk.END)
            entry_user.delete(0, tk.END)
            entry_pass.delete(0, tk.END)
            refresh_table()

        tk.Button(form_frame, text="Add", command=add_entry).grid(
            row=0, column=6, padx=10
        )

        # Table View
        table_frame = tk.Frame(self.container, padx=10, pady=5)
        table_frame.pack(fill="both", expand=True)

        columns = ("ID", "Service", "Username", "Password")
        tree = ttk.Treeview(
            table_frame, columns=columns, show="headings", height=10
        )
        tree.heading("ID", text="ID")
        tree.heading("Service", text="Service")
        tree.heading("Username", text="Username")
        tree.heading("Password", text="Password")

        tree.column("ID", width=40, anchor="center")
        tree.column("Service", width=150)
        tree.column("Username", width=150)
        tree.column("Password", width=150)
        tree.pack(fill="both", expand=True)

        def refresh_table():
            for row in tree.get_children():
                tree.delete(row)
            for item in db.get_credentials(self.fernet):
                tree.insert("", tk.END, values=item)

        # Action Buttons (Delete / Copy)
        action_frame = tk.Frame(self.container, padx=10, pady=10)
        action_frame.pack(fill="x")

        def copy_selected_password():
            selected = tree.selection()
            if not selected:
                messagebox.showwarning(
                    "Warning", "Select an item to copy password."
                )
                return
            item = tree.item(selected[0])
            pw = item["values"][3]
            self.clipboard_clear()
            self.clipboard_append(pw)
            messagebox.showinfo("Copied", "Password copied to clipboard.")

        def delete_selected():
            selected = tree.selection()
            if not selected:
                messagebox.showwarning("Warning", "Select an item to delete.")
                return
            item = tree.item(selected[0])
            cred_id = item["values"][0]
            db.delete_credential(cred_id)
            refresh_table()

        tk.Button(
            action_frame,
            text="Copy Password",
            command=copy_selected_password,
        ).pack(side="left", padx=5)
        tk.Button(
            action_frame, text="Delete Entry", command=delete_selected
        ).pack(side="left", padx=5)

        refresh_table()

    def lock_vault(self):
        self.fernet = None
        self.show_login_screen()


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()
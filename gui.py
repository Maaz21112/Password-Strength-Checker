import tkinter as tk
from tkinter import ttk, messagebox
import math
import string
import hashlib
import requests
import getpass
import threading
from customtkinter import CTk, CTkEntry, CTkButton, CTkCheckBox, CTkLabel  # Optional for modern UI

class PasswordCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Checker")
        
        # Configure main frame
        self.main_frame = ttk.Frame(root, padding=20)
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Password Entry
        self.create_password_entry()
        
        # Results Display
        self.create_results_section()
        
        # Load common passwords
        self.common_passwords = self.load_common_passwords()
        
    def create_password_entry(self):
        frame = ttk.Frame(self.main_frame)
        frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(frame, text="Enter Password:").pack(side=tk.LEFT)
        
        self.password_entry = ttk.Entry(frame, show="*", width=30)
        self.password_entry.pack(side=tk.LEFT, padx=10)
        self.password_entry.bind("<KeyRelease>", self.on_password_change)
        
        self.show_password_var = tk.BooleanVar()
        ttk.Checkbutton(frame, text="Show", variable=self.show_password_var,
                       command=self.toggle_password_visibility).pack(side=tk.LEFT)
        
        ttk.Button(frame, text="Check", command=self.check_password).pack(side=tk.RIGHT)
    
    def create_results_section(self):
        # NIST Guidelines
        self.nist_label = ttk.Label(self.main_frame, text="NIST Guidelines: ")
        self.nist_label.pack(anchor=tk.W)
        
        # Entropy & Strength
        self.entropy_label = ttk.Label(self.main_frame, text="Entropy: ")
        self.entropy_label.pack(anchor=tk.W)
        self.strength_label = ttk.Label(self.main_frame, text="Strength: ")
        self.strength_label.pack(anchor=tk.W)
        
        # Suggestions
        self.suggestions_label = ttk.Label(self.main_frame, text="Suggestions:")
        self.suggestions_label.pack(anchor=tk.W)
        self.suggestions_text = tk.Text(self.main_frame, height=4, width=50)
        self.suggestions_text.pack(anchor=tk.W)
        
        # Breach Check
        self.breach_label = ttk.Label(self.main_frame, text="Breach Check: ")
        self.breach_label.pack(anchor=tk.W)
        
    def load_common_passwords(self):
        try:
            with open('common_passwords.txt', 'r', encoding='utf-8') as f:
                return set(f.read().splitlines())
        except FileNotFoundError:
            messagebox.showwarning("Warning", "common_passwords.txt not found")
            return set()
    
    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def on_password_change(self, event=None):
        self.update_strength_indicator()
    
    def update_strength_indicator(self):
        password = self.password_entry.get()
        entropy = self.calculate_entropy(password)
        strength = self.get_strength(entropy)
        color = self.get_strength_color(strength)
        self.strength_label.config(text=f"Strength: {strength}", foreground=color)
    
    def check_password(self):
        password = self.password_entry.get()
        
        # NIST Check
        nist_valid, nist_msg = self.check_nist_guidelines(password)
        self.nist_label.config(text=f"NIST Guidelines: {nist_msg}")
        
        # Entropy & Strength
        entropy = self.calculate_entropy(password)
        strength = self.get_strength(entropy)
        color = self.get_strength_color(strength)
        self.entropy_label.config(text=f"Entropy: {entropy:.2f} bits")
        self.strength_label.config(text=f"Strength: {strength}", foreground=color)
        
        # Suggestions
        suggestions = self.generate_suggestions(password)
        self.suggestions_text.delete(1.0, tk.END)
        if suggestions:
            self.suggestions_text.insert(tk.END, "\n".join(suggestions))
        else:
            self.suggestions_text.insert(tk.END, "No suggestions. Great password!")
            
        # Breach Check (in background thread)
        threading.Thread(target=self.check_breach_thread, args=(password,)).start()
    
    def check_breach_thread(self, password):
        breached, breach_msg = self.check_breached(password)
        self.root.after(0, lambda: self.breach_label.config(
            text=f"Breach Check: {breach_msg}",
            foreground="red" if breached else "green"
        ))
    
    # Existing functions from previous implementation (slightly modified)
    def check_nist_guidelines(self, password):
        if len(password) < 8:
            return False, "Too short (min 8 chars)"
        if len(password) > 64:
            return False, "Too long (max 64 chars)"
        if password in self.common_passwords:
            return False, "Common password"
        return True, "Meets requirements"
    
    def calculate_entropy(self, password):
        charset_size = 0
        if any(c in string.ascii_lowercase for c in password):
            charset_size += 26
        if any(c in string.ascii_uppercase for c in password):
            charset_size += 26
        if any(c in string.digits for c in password):
            charset_size += 10
        if any(c in string.punctuation for c in password):
            charset_size += 32
        if charset_size == 0:
            return 0
        return len(password) * math.log2(charset_size)
    
    def get_strength(self, entropy):
        if entropy < 28: return "Very Weak"
        elif entropy < 36: return "Weak"
        elif entropy < 60: return "Moderate"
        elif entropy < 128: return "Strong"
        else: return "Very Strong"
    
    def get_strength_color(self, strength):
        colors = {
            "Very Weak": "red",
            "Weak": "orange",
            "Moderate": "yellow",
            "Strong": "lightgreen",
            "Very Strong": "darkgreen"
        }
        return colors.get(strength, "black")
    
    def generate_suggestions(self, password):
        suggestions = []
        if len(password) < 12:
            suggestions.append("Use at least 12 characters")
        if not any(c.isupper() for c in password):
            suggestions.append("Add uppercase letters")
        if not any(c.islower() for c in password):
            suggestions.append("Add lowercase letters")
        if not any(c.isdigit() for c in password):
            suggestions.append("Include numbers")
        if not any(c in string.punctuation for c in password):
            suggestions.append("Add special characters")
        return suggestions
    
    def check_breached(self, password):
        try:
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
            if response.status_code == 200:
                for line in response.text.splitlines():
                    if line.split(':')[0] == suffix:
                        return True, f"Breached ({line.split(':')[1]} times)"
                return False, "Not breached"
            return False, "API Error"
        except Exception:
            return False, "Connection failed"

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordCheckerApp(root)
    root.mainloop()
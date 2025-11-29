"""
advanced_password_generator.py

Advanced Password Generator GUI using Tkinter.

Features:
- Cryptographically secure randomization with `secrets`.
- Options for uppercase/lowercase/digits/symbols.
- Exclude specific characters and remove ambiguous characters.
- Enforce at least one character from each selected category.
- Clipboard integration (Tk clipboard, optional pyperclip fallback).
- Password strength (entropy) estimate and friendly guidance.
- Save password to file.
- Clean, readable, modular code for internship submission.

Author: ChatGPT (GPT-5 Thinking mini)
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import secrets
import string
import math

# Optional: try to import pyperclip for clipboard fallback
try:
    import pyperclip
    _HAS_PYPERCLIP = True
except Exception:
    _HAS_PYPERCLIP = False

# Ambiguous characters commonly avoided
AMBIGUOUS_CHARS = "Il1O0`'\".,;:|\\/[]{}()<>"

# -------------------------
# Helper functions
# -------------------------
def build_charset(use_upper, use_lower, use_digits, use_symbols, exclude, remove_ambiguous):
    """Build a charset string from the selected categories and exclusion rules."""
    parts = []
    if use_upper:
        parts.append(string.ascii_uppercase)
    if use_lower:
        parts.append(string.ascii_lowercase)
    if use_digits:
        parts.append(string.digits)
    if use_symbols:
        # basic safe symbol set; adjust as needed
        parts.append("!@#$%^&*()-_=+[]{};:,.<>/?~")
    charset = "".join(parts)
    if exclude:
        charset = "".join(ch for ch in charset if ch not in exclude)
    if remove_ambiguous:
        charset = "".join(ch for ch in charset if ch not in AMBIGUOUS_CHARS)
    # Remove duplicates and keep order stable
    seen = set()
    final = []
    for ch in charset:
        if ch not in seen:
            seen.add(ch)
            final.append(ch)
    return "".join(final)

def estimate_entropy(length, charset_size):
    """Estimate entropy bits = length * log2(charset_size)."""
    if length <= 0 or charset_size <= 0:
        return 0.0
    return length * math.log2(charset_size)

def strength_label(entropy_bits):
    """Return label and color for the entropy value (guidance)."""
    if entropy_bits < 28:
        return "Very Weak", "#d9534f"
    if entropy_bits < 36:
        return "Weak", "#f0ad4e"
    if entropy_bits < 60:
        return "Reasonable", "#f7e12b"
    if entropy_bits < 128:
        return "Strong", "#5cb85c"
    return "Very Strong", "#2ca02c"

def copy_to_clipboard(root, text):
    """Try copying to clipboard using Tk, fall back to pyperclip if available."""
    try:
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()  # sometimes required on certain platforms
        return True, "Copied to clipboard (Tk)."
    except Exception:
        if _HAS_PYPERCLIP:
            try:
                pyperclip.copy(text)
                return True, "Copied to clipboard (pyperclip)."
            except Exception as e:
                return False, f"pyperclip failed: {e}"
        return False, "Clipboard copy failed."

def generate_password(length, charset, enforce_rules, use_upper, use_lower, use_digits, use_symbols, disallow_repeats=False):
    """Generate password with optional enforcement of at least one from each selected category."""
    if not charset:
        raise ValueError("Character set is empty. Choose categories or change exclusions.")
    if length <= 0:
        raise ValueError("Length must be positive.")

    if disallow_repeats and length > len(charset):
        raise ValueError(f"Cannot generate {length}-char password without repeating characters when only {len(charset)} unique characters are available.")

    if not enforce_rules:
        if disallow_repeats:
            # draw unique characters without replacement
            return "".join(secrets.choice(charset) for _ in range(length)) if length <= len(charset) else "".join(secrets.choice(charset) for _ in range(length))
        return "".join(secrets.choice(charset) for _ in range(length))

    # Build category maps filtered by charset
    category_map = {}
    if use_upper:
        category_map['upper'] = [c for c in string.ascii_uppercase if c in charset]
    if use_lower:
        category_map['lower'] = [c for c in string.ascii_lowercase if c in charset]
    if use_digits:
        category_map['digits'] = [c for c in string.digits if c in charset]
    if use_symbols:
        category_map['symbols'] = [c for c in "!@#$%^&*()-_=+[]{};:,.<>/?~" if c in charset]

    selected_cats = [k for k in category_map.keys()]

    # Check each selected category has at least one available char
    for cat in selected_cats:
        if not category_map[cat]:
            raise ValueError(f"No characters available for category: {cat}. Adjust exclusions or settings.")

    if length < len(selected_cats):
        raise ValueError(f"Length {length} is too short to include one character from each selected category ({len(selected_cats)}).")

    password_chars = []
    # Guarantee one char per selected category
    for cat in selected_cats:
        ch = secrets.choice(category_map[cat])
        password_chars.append(ch)

    # Fill the rest
    remaining = length - len(password_chars)
    if disallow_repeats:
        # Remove already used characters from available pool
        available = [c for c in charset if c not in password_chars]
        if remaining > len(available):
            raise ValueError("Not enough unique characters left to fill password without repeats.")
        for _ in range(remaining):
            pick = secrets.choice(available)
            password_chars.append(pick)
            available.remove(pick)
    else:
        for _ in range(remaining):
            password_chars.append(secrets.choice(charset))

    # Shuffle
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)

# -------------------------
# GUI Application
# -------------------------
class PasswordGeneratorApp(ttk.Frame):
    def __init__(self, root):
        super().__init__(root, padding=12)
        self.root = root
        root.title("Advanced Password Generator — Oasis Internship")
        root.resizable(False, False)
        self.grid(sticky="nsew")

        # Variables
        self.length_var = tk.IntVar(value=16)
        self.use_upper_var = tk.BooleanVar(value=True)
        self.use_lower_var = tk.BooleanVar(value=True)
        self.use_digits_var = tk.BooleanVar(value=True)
        self.use_symbols_var = tk.BooleanVar(value=True)
        self.exclude_var = tk.StringVar(value="")
        self.ambiguous_var = tk.BooleanVar(value=True)
        self.enforce_var = tk.BooleanVar(value=True)
        self.disallow_repeats_var = tk.BooleanVar(value=False)
        self.password_var = tk.StringVar(value="")
        self.entropy_var = tk.DoubleVar(value=0.0)

        self._build_ui()

    def _build_ui(self):
        # Options
        opts = ttk.LabelFrame(self, text="Options", padding=10)
        opts.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        ttk.Label(opts, text="Length:").grid(row=0, column=0, sticky="w")
        ttk.Spinbox(opts, from_=4, to=256, textvariable=self.length_var, width=6).grid(row=0, column=1, sticky="w", padx=(6,10))

        ttk.Checkbutton(opts, text="Uppercase (A-Z)", variable=self.use_upper_var).grid(row=1, column=0, sticky="w")
        ttk.Checkbutton(opts, text="Lowercase (a-z)", variable=self.use_lower_var).grid(row=1, column=1, sticky="w")
        ttk.Checkbutton(opts, text="Digits (0-9)", variable=self.use_digits_var).grid(row=2, column=0, sticky="w")
        ttk.Checkbutton(opts, text="Symbols (!@#$...)", variable=self.use_symbols_var).grid(row=2, column=1, sticky="w")

        ttk.Checkbutton(opts, text="Enforce at least one from each selected type", variable=self.enforce_var).grid(row=3, column=0, columnspan=2, sticky="w", pady=(6,0))
        ttk.Checkbutton(opts, text="Remove ambiguous characters (Il1O0...)", variable=self.ambiguous_var).grid(row=4, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(opts, text="Disallow repeated characters", variable=self.disallow_repeats_var).grid(row=5, column=0, columnspan=2, sticky="w")

        ttk.Label(opts, text="Exclude characters (optional):").grid(row=6, column=0, sticky="w", pady=(8,0))
        ttk.Entry(opts, textvariable=self.exclude_var, width=28).grid(row=6, column=1, sticky="w", pady=(8,0))

        # Generate / Output
        out = ttk.LabelFrame(self, text="Generate", padding=10)
        out.grid(row=1, column=0, sticky="ew", padx=5, pady=5)

        pwd_entry = ttk.Entry(out, textvariable=self.password_var, font=("Consolas", 12), width=44)
        pwd_entry.grid(row=0, column=0, columnspan=3, pady=(0,8))
        pwd_entry.configure(state="readonly")
        self.pwd_entry = pwd_entry

        gen_btn = ttk.Button(out, text="Generate", command=self.on_generate)
        gen_btn.grid(row=1, column=0, sticky="w", padx=(0,6))
        copy_btn = ttk.Button(out, text="Copy", command=self.on_copy)
        copy_btn.grid(row=1, column=1, sticky="w", padx=(0,6))
        save_btn = ttk.Button(out, text="Save...", command=self.on_save)
        save_btn.grid(row=1, column=2, sticky="e")

        self.str_label = ttk.Label(out, text="Strength: N/A")
        self.str_label.grid(row=2, column=0, columnspan=3, sticky="w", pady=(8,0))
        self.ent_label = ttk.Label(out, text="Entropy: 0 bits")
        self.ent_label.grid(row=3, column=0, columnspan=3, sticky="w")

        # Tips
        tips = ttk.LabelFrame(self, text="Tips", padding=10)
        tips.grid(row=2, column=0, sticky="ew", padx=5, pady=5)
        ttk.Label(tips, text="Use a length >= 12 and enable multiple character types.\nUse a password manager to store long unique passwords.", wraplength=500).grid(row=0, column=0)

        # Layout polish
        for child in opts.winfo_children():
            child.grid_configure(padx=4, pady=4)
        for child in out.winfo_children():
            child.grid_configure(padx=4, pady=4)

    def on_generate(self):
        length = self.length_var.get()
        use_upper = self.use_upper_var.get()
        use_lower = self.use_lower_var.get()
        use_digits = self.use_digits_var.get()
        use_symbols = self.use_symbols_var.get()
        exclude = self.exclude_var.get().strip()
        remove_ambiguous = self.ambiguous_var.get()
        enforce = self.enforce_var.get()
        disallow_repeats = self.disallow_repeats_var.get()

        try:
            if length <= 0:
                raise ValueError("Password length must be positive.")
            if not (use_upper or use_lower or use_digits or use_symbols):
                raise ValueError("Select at least one character type.")
            charset = build_charset(use_upper, use_lower, use_digits, use_symbols, exclude, remove_ambiguous)
            if not charset:
                raise ValueError("Character set is empty after applying exclusions. Change exclusions or selections.")
            # Generate
            pwd = generate_password(length, charset, enforce, use_upper, use_lower, use_digits, use_symbols, disallow_repeats)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            return

        self.password_var.set(pwd)
        entropy = estimate_entropy(length, len(charset))
        label, color = strength_label(entropy)
        self.str_label.config(text=f"Strength: {label}")
        self.ent_label.config(text=f"Entropy: {entropy:.1f} bits (charset size: {len(charset)})")
        # Set color where supported
        try:
            self.str_label.config(foreground=color)
        except Exception:
            pass

    def on_copy(self):
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showinfo("Nothing to copy", "Generate a password first.")
            return
        ok, msg = copy_to_clipboard(self.root, pwd)
        if ok:
            messagebox.showinfo("Copied", msg)
        else:
            messagebox.showwarning("Clipboard Failed", msg)

    def on_save(self):
        pwd = self.password_var.get()
        if not pwd:
            messagebox.showinfo("Nothing to save", "Generate a password first.")
            return
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(pwd + "\n")
                messagebox.showinfo("Saved", f"Password saved to:\n{filename}")
            except Exception as e:
                messagebox.showerror("Save Error", str(e))


def main():
    root = tk.Tk()
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    app = PasswordGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()

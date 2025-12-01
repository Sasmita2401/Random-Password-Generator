A powerful and secure Advanced Password Generator built using Python Tkinter for the Oasis Infobyte Internship Task.
This GUI tool generates cryptographically strong passwords with customization options, strength analysis, entropy calculation, clipboard copy, and file save support — ideal for internship demonstration.

Objective
To build a secure and fully functional Password Generator using Python, implementing GUI components, strong cryptographic libraries, input validation, and user-friendly features that meet internship task requirements.

Features
Cryptographically secure password generation (secrets module)
Choose character types: uppercase, lowercase, digits, symbols
Option to remove ambiguous characters (Il1O0` etc.)
Exclude user-defined characters
Enforce at least one character from each selected category
Option to disallow repeated characters
Password strength label (Weak → Very Strong)
Entropy calculation (bits)
Copy password to clipboard
Save password to a text file
Clean Tkinter GUI suitable for internship submission

Tools & Technologies Used
Python 3
Tkinter (GUI)
Secrets (secure random)
String & Math libraries
Pillow / Pyperclip (optional support)

How to Run the Project

1. Install Required Packages
Most modules used are built-in.
Optional recommended installation:
pip install pyperclip

2. Run the Python File
Make sure all .py files are in the same folder,then run:

python advanced_password_generator.py
Make sure all .py files are in the same folder, then run:

python advanced_password_generator.py

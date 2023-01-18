import json
from PyQt5 import QtWidgets, QtCore
import string
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class Credentials:
    def __init__(self, username:str, site:str,password:str):
        self.username = username
        self.site = site
        self.password = password

class PasswordGeneratorWindow(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Password Generator")
        self.setFixedSize(300,200)
        
        # Create the password length label and spin box
        self.length_label = QtWidgets.QLabel("Password length:")
        self.length_spinbox = QtWidgets.QSpinBox()
        self.length_spinbox.setRange(1, 100)
        self.length_spinbox.setValue(10)
        
        # Create the generate button
        self.generate_button = QtWidgets.QPushButton("Generate")
        self.generate_button.clicked.connect(self.generate_password)
        
        # Create the password display label
        self.password_label = QtWidgets.QLineEdit()
        self.password_label.setReadOnly(True)
        self.password_label.setPlaceholderText("Generated password will appear here")
        
        # Create a layout and add the widgets
        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.length_label)
        layout.addWidget(self.length_spinbox)
        layout.addWidget(self.generate_button)
        layout.addWidget(self.password_label)
        self.setLayout(layout)
        save_button = QtWidgets.QPushButton("Save")
        save_button.clicked.connect(lambda:self.save_credentials(username,site,password))
        layout.addWidget(save_button)
        self.setLayout(layout)
    
    def save_credentials(self,username,site,password):
        credentials = Credentials(username,site,password)
        # Encrypt the credentials using AES
        key = b"yoursecretkey12345" # replace with your own key
        cipher = AES.new(key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(json.dumps(credentials.__dict__).encode())
        # Write the encrypted credentials to a file
        with open("password.bin", "wb") as f:
            [ f.write(x) for x in (nonce, tag, ciphertext) ]
        self.password_label.setText("Credentials saved successfully!")
    


    
    def read_password(self):
        """
        Read the encrypted password from the file, decrypt it and return the decrypted password.
        """
        credentials = None
        try:
            # Read the encrypted password from the file
            with open("password.bin", "rb") as f:
                nonce, tag, ciphertext = [ f.read(x) for x in (16, 16, -1) ]
            # Decrypt the password using AES
            key = b"yoursecretkey12345" # replace with your own key
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            decrypted_credentials = cipher.decrypt(ciphertext).decode()
            credentials = json.loads(decrypted_credentials,object_hook=lambda d: Credentials(d['username'], d['site'], d['password']))
        except FileNotFoundError:
            self.password_label.setText("Error: password file not found")
        except ValueError:
            self.password_label.setText("Error: decryption failed")
        except Exception as e:
            self.password_label.setText(f"Error: {e}")
        return credentials

    def generate_password(self):
        """
        Generate a secure password and display it in the password label.
        """
        # Get the password length from the spin box
        length = self.length_spinbox.value()
        
        # Generate the password 
        chars = string.printable
        chars = chars.replace("l", "")
        chars = chars.replace("1", "")
        chars = chars.replace("I", "")
        chars = list(chars)
        random.shuffle(chars)
        chars = chars[:length]
        password = "".join(chars)
        
        # Display the password in the password label
        self.password_label.setText(password)

        # Get the username and site using a pop-up input box
        username, ok = QtWidgets.QInputDialog.getText(self, "Username", "Enter your username:")
        if not ok:
            return
        site, ok = QtWidgets.QInputDialog.getText(self, "Site", "Enter the site:")
        if not ok:
            self.show_password_dialog()

    def show_password_dialog(self):
               
        # Create a dialog with a line edit and a button
        dialog = QtWidgets.QDialog(self)
        dialog.setWindowTitle("Password")
        layout = QtWidgets.QVBoxLayout()
        password_label = QtWidgets.QLineEdit()
        password_label.setText(password)
        password_label.setReadOnly(True)
        layout.addWidget(password_label)
        save_button = QtWidgets.QPushButton("Save")
        save_button.clicked.connect(dialog.accept)
        layout.addWidget(save_button)
        dialog.setLayout(layout)
        
        # Show the dialog and store the password if the user clicks "Save"
        if dialog.exec_() == QtWidgets.QDialog.Accepted:
            credentials = Credentials(username,site,password)
            # Encrypt the credentials using AES
            key = b"yoursecretkey12345" # replace with your own key
            cipher = AES.new(key, AES.MODE_EAX)
            credentials_text = json.dumps(credentials.__dict__)
            ciphertext, tag = cipher.encrypt_and_digest(credentials_text.encode())
            # Write the encrypted credentials to a file
            with open("password.bin", "wb") as f:
                [ f.write(x) for x in (cipher.nonce, tag, ciphertext) ]
        
        app.exec_()

        self.password_label.setText(password)

app = QtWidgets.QApplication([])
window = PasswordGeneratorWindow()
window.show()
app.exec_()
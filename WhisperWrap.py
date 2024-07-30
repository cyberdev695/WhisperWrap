import customtkinter
from tkinter import *
import tkinter.filedialog
from tkinter import messagebox
from PIL import ImageTk
from PIL import Image
from io import BytesIO
from cryptography.fernet import Fernet
import base64

# Initialize app theme to dark mode
mode = "dark"


class stego_image:
    output_imageSize = 0

    def __init__(self):
        self.key = None
        self.file_to_hide = None

    # Creates the main menu frame where the user can choose to proceed to the encode frame, decode frame, or toggle the
    # theme.
    def main_menu(self, root):
        root.title("WhisperWrap")
        root.wm_iconbitmap("improved logo.ico")
        root.minsize(800, 650)
        customtkinter.set_appearance_mode("system")
        customtkinter.set_default_color_theme("dark-blue")

        frame = customtkinter.CTkFrame(master=root)
        frame.pack(pady=20, padx=60, fill="both", expand=True)

        title = customtkinter.CTkLabel(master=frame,
                                       text="\nWelcome to WhisperWrap:\n Orbiter of the World of Steganography!\n",
                                       font=('Roboto', 30, 'bold'))
        title.pack(pady=(0, 20))

        logo_image = Image.open("improved logo.png")
        resize_image = logo_image.resize((400, 400))
        logo_image = ImageTk.PhotoImage(resize_image)
        logo_label = Label(frame, image=logo_image)
        logo_label.image = logo_image  # reference
        logo_label.pack(pady=(0, 20))

        selection_label = customtkinter.CTkLabel(master=frame,
                                                 text="\nChoose Your Galactic Mission Below",
                                                 font=('Roboto', 24, 'bold'))
        selection_label.pack(pady=(0, 20))

        encode_button = customtkinter.CTkButton(master=frame, text="Encode Image", font=('Roboto', 24, 'bold'),
                                                command=self.encode_frame1)
        encode_button.pack(pady=(0, 10))

        decode_button = customtkinter.CTkButton(master=frame, text="Decode Image", font=('Roboto', 24, 'bold'),
                                                command=self.decode_frame1)
        decode_button.pack(pady=(0, 10))

        theme_button = customtkinter.CTkButton(master=frame, text="Change Theme (Light/Dark)",
                                               font=('Roboto', 20, 'bold'), command=self.toggle_theme, fg_color='grey')
        theme_button.pack(pady=(0, 10))

    def encode_frame1(self):
        for widget in root.winfo_children():
            widget.destroy()

        encode_frame = customtkinter.CTkFrame(master=root)
        encode_frame.pack(pady=40, padx=60, fill="both", expand=True)

        encode_title = customtkinter.CTkLabel(master=encode_frame,
                                              text="\nSafeguard Your Secrets Across the Universe!\n",
                                              font=('Roboto', 30, 'bold'))
        encode_title.pack(pady=(0, 20))

        encode_image = Image.open("MadAlien.jpg")
        resize_image = encode_image.resize((300, 300))
        encode_image = ImageTk.PhotoImage(resize_image)
        encode_label = Label(encode_frame, image=encode_image)
        encode_label.image = encode_image  # reference
        encode_label.pack(pady=(0, 75))

        image_selection = customtkinter.CTkLabel(master=encode_frame,
                                                 text="\nSelect an image you want to hide secrets in (.jpg, .png):\n ",
                                                 font=('Roboto', 24, 'bold'))
        image_selection.pack(fill="x", pady=(0, 20))

        browse_button = customtkinter.CTkButton(master=encode_frame, text="Choose Image", font=('Roboto', 24, 'bold'),
                                                command=lambda: self.encode_frame2())
        browse_button.pack(fill="x", pady=(0, 20))

        back_button = customtkinter.CTkButton(master=encode_frame, text="Back", font=('Roboto', 20, 'bold'),
                                              command=self.back, fg_color='red')
        back_button.pack(fill="x", pady=(0, 20))

        theme_button = customtkinter.CTkButton(master=encode_frame, text="Change Theme (Light/Dark)",
                                               font=('Roboto', 20, 'bold'), command=self.toggle_theme, fg_color='grey')
        theme_button.pack(fill="x", pady=(0, 20))

    def decode_frame1(self):
        for widget in root.winfo_children():
            widget.destroy()

        decode_frame = customtkinter.CTkFrame(master=root)
        decode_frame.pack(pady=20, padx=60, fill="both", expand=True)

        decode_title = customtkinter.CTkLabel(master=decode_frame, text="\nBring Secrets to Light Years!\n",
                                              font=('Roboto', 30, 'bold'))
        decode_title.pack(pady=(0, 20))

        decode_image = Image.open("ShootingStarFile.jpg")
        resize_image = decode_image.resize((300, 300))
        decode_image = ImageTk.PhotoImage(resize_image)
        decode_label = Label(decode_frame, image=decode_image)
        decode_label.image = decode_image  # reference
        decode_label.pack(pady=(0, 75))

        image_selection = customtkinter.CTkLabel(master=decode_frame,
                                                 text="\nChoose an image with secrets inside (.jpg, .png):\n ",
                                                 font=('Roboto', 24, 'bold'))
        image_selection.pack(fill="x", pady=(0, 20))

        browse_button = customtkinter.CTkButton(master=decode_frame, text="Choose Image", font=('Roboto', 24, 'bold'),
                                                command=lambda: self.decode_frame2())
        browse_button.pack(fill="x", pady=(0, 20))

        back_button = customtkinter.CTkButton(master=decode_frame, text="Back", font=('Roboto', 20, 'bold'),
                                              command=self.back, fg_color='red')
        back_button.pack(fill="x", pady=(0, 20))

        theme_button = customtkinter.CTkButton(master=decode_frame, text="Change Theme (Light/Dark)",
                                               font=('Roboto', 20, 'bold'), command=self.toggle_theme, fg_color='grey')
        theme_button.pack(fill="x", pady=(0, 20))

    def encode_frame2(self):
        for widget in root.winfo_children():
            widget.destroy()

        encode2_frame = customtkinter.CTkFrame(master=root)
        encode2_frame.pack(pady=40, padx=60, fill="both", expand=True)

        user_file = tkinter.filedialog.askopenfilename(
            filetypes=[('PNG Images', '*.png'), ('JPEG Images', '*.jpeg'), ('JPG Images', '*.jpg'),
                       ('All Files', '*.*')])
        if not user_file:
            messagebox.showerror("Error", "You have selected nothing!")
            self.back()
        else:
            my_img = Image.open(user_file)
            new_image = my_img.resize((500, 300))
            img = ImageTk.PhotoImage(new_image)

            encode2_title = customtkinter.CTkLabel(master=encode2_frame, text="\nCosmic Encoding Station",
                                                  font=('Roboto', 30, 'bold'))
            encode2_title.pack(pady=(0, 20))

            label3 = customtkinter.CTkLabel(encode2_frame, text='Selected Image', font=('Roboto', 14, 'bold'))
            label3.pack(pady=(0, 10))

            board = Label(encode2_frame, image=img)
            board.image = img
            board.pack(pady=(0, 20))

            file_selection = customtkinter.CTkLabel(master=encode2_frame, text='Select a file to hide:',
                                                    font=('Roboto', 14, 'bold'))
            file_selection.pack(pady=(0, 10))

            browse_file_button = customtkinter.CTkButton(master=encode2_frame, text="Choose File",
                                                         font=('Roboto', 24, 'bold'), command=self.select_file)
            browse_file_button.pack(pady=(0, 20))

            label_password = customtkinter.CTkLabel(encode2_frame, text='\nEnter password (Required):\n',
                                                    font=('Roboto', 14, 'bold'))
            label_password.pack()

            password_frame = Frame(encode2_frame)
            password_frame.pack(pady=(0, 20))

            password_entry = customtkinter.CTkEntry(password_frame, show='*', font=('Roboto', 14, 'bold'))
            password_entry.pack(side=LEFT)

            show_password_button = customtkinter.CTkButton(password_frame, text='👁', width=40,
                                                           command=lambda: self.toggle_password_visibility(
                                                               password_entry))
            show_password_button.pack(side=LEFT, padx=(5, 0))

            encode_button = customtkinter.CTkButton(encode2_frame,
                                                    text='Save Encoded Image File', font=('Roboto', 20, 'bold'),
                                                    command=lambda: self.enc_fun_file(password_entry, my_img))
            encode_button.pack(pady=(0, 10))

            back_button = customtkinter.CTkButton(encode2_frame, text='Back', font=('Roboto', 20, 'bold'),
                                                  command=self.back, fg_color='red')
            back_button.pack()

    def select_file(self):
        self.file_to_hide = tkinter.filedialog.askopenfilename(filetypes=[('All Files', '*.*')])
        if not self.file_to_hide:
            messagebox.showerror("Error", "You have selected nothing!")

    def enc_fun_file(self, password_entry, image):
        if not self.file_to_hide or not self.file_to_hide:
            messagebox.showerror("Error", "No file selected to hide.")
            return

        password = password_entry.get()

        with open(self.file_to_hide, 'rb') as file:
            data = file.read()

        if len(data) == 0:
            messagebox.showerror("Error", "The selected file is empty.")
            return

        key = self.generate_key(password)
        cipher = Fernet(key)

        try:
            encrypted_data = cipher.encrypt(data)
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
            return

        self.encode_image(image, encrypted_data)

    def encode_image(self, image, data):
        encoded = self.encode_enc(image, data)

        my_file = BytesIO()
        temp_image_name = "temp_image.png"
        encoded.save(temp_image_name)
        temp_image = Image.open(temp_image_name)
        temp_image.save(my_file, format='PNG')
        self.output_imageSize = my_file.tell()
        my_file.close()

        if self.output_imageSize <= 10000000000:
            file_name = tkinter.filedialog.asksaveasfilename(
                initialfile='Encoded_Image.png', defaultextension=".png",
                filetypes=[("PNG file", "*.png"), ("All Files", "*.*")])
            if file_name:
                encoded.save(file_name)
                messagebox.showinfo("Success", "Image encoded and saved successfully!")
            else:
                messagebox.showerror("Error", "The file was not saved!")
        else:
            messagebox.showerror("Error", "Encoded data is too large to save!")

    def encode_enc(self, image, data):
        # Convert image to RGBA to include alpha channel
        img = image.convert('RGBA')

        # Convert data to binary string
        binary_data = ''.join([format(byte, '08b') for byte in data])

        # Load pixel data
        pixels = img.load()
        data_index = 0

        # Embed data into the alpha channel of each pixel
        for i in range(img.size[0]):
            for j in range(img.size[1]):
                if data_index < len(binary_data):
                    r, g, b, a = pixels[i, j]
                    # Modify the least significant bit of the alpha channel
                    a = (a & 0xFE) | int(binary_data[data_index])
                    # Update the pixel with the new alpha value
                    pixels[i, j] = (r, g, b, a)
                    # Move to the next bit of data
                    data_index += 1

        return img

    def decode_frame2(self):
        for widget in root.winfo_children():
            widget.destroy()

        decode2_frame = customtkinter.CTkFrame(master=root)
        decode2_frame.pack(pady=40, padx=60, fill="both", expand=True)

        user_file = tkinter.filedialog.askopenfilename(
            filetypes=[('PNG Images', '*.png'), ('JPEG Images', '*.jpeg'), ('JPG Images', '*.jpg'),
                       ('All Files', '*.*')])
        if not user_file:
            messagebox.showerror("Error", "You have selected nothing!")
            self.back()
        else:
            my_img = Image.open(user_file)
            new_image = my_img.resize((500, 300))
            img = ImageTk.PhotoImage(new_image)

            decode2_title = customtkinter.CTkLabel(master=decode2_frame, text="\nCosmic Decoding Station",
                                                   font=('Roboto', 30, 'bold'))
            decode2_title.pack(pady=(0, 20))

            label3 = customtkinter.CTkLabel(decode2_frame, text='Selected Image', font=('Roboto', 14, 'bold'))
            label3.pack(pady=(0, 10))

            board = Label(decode2_frame, image=img)
            board.image = img
            board.pack(pady=(0, 20))

            label_password = customtkinter.CTkLabel(decode2_frame, text='\nEnter password (Required):\n',
                                                    font=('Roboto', 14, 'bold'))
            label_password.pack()

            password_frame = Frame(decode2_frame)
            password_frame.pack(pady=(0, 20))

            password_entry = customtkinter.CTkEntry(password_frame, show='*', font=('Roboto', 14, 'bold'))
            password_entry.pack(side=LEFT)

            show_password_button = customtkinter.CTkButton(password_frame, text='👁', width=40,
                                                           command=lambda: self.toggle_password_visibility(
                                                               password_entry))
            show_password_button.pack(side=LEFT, padx=(5, 0))

            decode_button = customtkinter.CTkButton(decode2_frame,
                                                    text='Decode Image', font=('Roboto', 20, 'bold'),
                                                    command=lambda: self.dec_fun(user_file, password_entry))
            decode_button.pack(pady=(0, 10))

            back_button = customtkinter.CTkButton(decode2_frame, text='Back', font=('Roboto', 20, 'bold'),
                                                  command=self.back, fg_color='red')
            back_button.pack()

    def dec_fun(self, image_path, password_entry):
        password = password_entry.get()
        if not password:
            messagebox.showerror("Error", "Wrong Password!")

        key = self.generate_key(password)
        cipher = Fernet(key)

        try:
            hidden_data = self.decode_image(image_path)
            decrypted_data = cipher.decrypt(hidden_data)

            save_file = tkinter.filedialog.asksaveasfilename(
                initialfile='Hidden_File', defaultextension="",
                filetypes=[("All Files", "*.*")])
            if save_file:
                with open(save_file, 'wb') as file:
                    file.write(decrypted_data)
                messagebox.showinfo("Success", "File decoded and saved successfully!")
            else:
                messagebox.showerror("Error", "The file was not saved!")
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def decode_image(self, image_path):
        img = Image.open(image_path).convert('RGBA')
        pixels = img.load()
        binary_data = []

        for i in range(img.size[0]):
            for j in range(img.size[1]):
                r, g, b, a = pixels[i, j]
                binary_data.append(str(a & 1))

        binary_data_str = ''.join(binary_data)
        byte_data = [binary_data_str[i:i + 8] for i in range(0, len(binary_data_str), 8)]
        decoded_data = bytearray([int(byte, 2) for byte in byte_data])

        return bytes(decoded_data)

    def toggle_theme(self):
        global mode
        if mode == "dark":
            customtkinter.set_appearance_mode("light")
            mode = "light"
        else:
            customtkinter.set_appearance_mode("dark")
            mode = "dark"

    def toggle_password_visibility(self, password_entry):
        if password_entry.cget('show') == '':
            password_entry.configure(show='*')
        else:
            password_entry.configure(show='')

    def back(self):
        for widget in root.winfo_children():
            widget.destroy()
        self.main_menu(root)

    def generate_key(self, password):
        if password:
            key = base64.urlsafe_b64encode(password.ljust(32)[:32].encode())
        else:
            key = base64.urlsafe_b64encode(Fernet.generate_key())
        return key


if __name__ == '__main__':
    root = customtkinter.CTk()
    app = stego_image()
    app.main_menu(root)
    root.mainloop()

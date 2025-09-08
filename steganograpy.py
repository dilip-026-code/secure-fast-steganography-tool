import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image

# ---------------------- SIMPLE XOR ENCRYPTION ---------------------- #
def encrypt_message(message, password):
    return ''.join(chr(ord(c) ^ ord(password[i % len(password)])) for i, c in enumerate(message))

def decrypt_message(encrypted, password):
    return encrypt_message(encrypted, password)  # XOR is reversible

# ---------------------- FAST ENCODE ---------------------- #
def encode_image(cover_path, out_path, message, password):
    # Encrypt message with password
    encrypted = encrypt_message(message, password)
    img = Image.open(cover_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    # Convert encrypted message to binary + delimiter
    data = encrypted.encode('utf-8') + b'<<<END>>>'
    binary_data = ''.join([f'{byte:08b}' for byte in data])
    data_len = len(binary_data)

    pixels = list(img.getdata())

    # Check if message fits into image
    if data_len > len(pixels) * 3:
        raise ValueError("Message too large for this image!")

    new_pixels = []
    data_index = 0

    for r, g, b in pixels:
        if data_index < data_len:
            r = (r & ~1) | int(binary_data[data_index]); data_index += 1
        if data_index < data_len:
            g = (g & ~1) | int(binary_data[data_index]); data_index += 1
        if data_index < data_len:
            b = (b & ~1) | int(binary_data[data_index]); data_index += 1
        new_pixels.append((r, g, b))

    img.putdata(new_pixels)
    img.save(out_path, "PNG")

# ---------------------- FAST DECODE ---------------------- #
def decode_image(stego_path, password):
    img = Image.open(stego_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = list(img.getdata())
    binary_data = ''.join(
        f"{r & 1}{g & 1}{b & 1}" for r, g, b in pixels
    )

    # Split into bytes
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    decoded_bytes = bytearray()

    for byte in all_bytes:
        decoded_bytes.append(int(byte, 2))
        if decoded_bytes.endswith(b'<<<END>>>'):
            decoded_bytes = decoded_bytes[:-8]
            break

    encrypted = decoded_bytes.decode('utf-8', errors="ignore")
    return decrypt_message(encrypted, password)

# ---------------------- GUI ---------------------- #
class StegoApp:
    def __init__(self, root):
        self.root = root
        root.title("Secure & Fast Steganography Tool")
        root.geometry("500x450")

        self.cover_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.password = tk.StringVar()

        tk.Label(root, text="Select Cover Image:").pack()
        tk.Entry(root, textvariable=self.cover_path, width=50).pack()
        tk.Button(root, text="Browse", command=self.browse_cover).pack()

        tk.Label(root, text="Save Stego Image As:").pack()
        tk.Entry(root, textvariable=self.output_path, width=50).pack()
        tk.Button(root, text="Save As", command=self.browse_output).pack()

        tk.Label(root, text="Password (Required):").pack()
        tk.Entry(root, textvariable=self.password, show="*", width=50).pack()

        tk.Label(root, text="Message to Hide:").pack()
        self.msg_text = tk.Text(root, height=5, width=50)
        self.msg_text.pack()

        tk.Button(root, text="Encode", command=self.encode).pack(pady=5)
        tk.Button(root, text="Decode", command=self.decode).pack(pady=5)

    def browse_cover(self):
        path = filedialog.askopenfilename(filetypes=[("PNG/BMP Images", "*.png;*.bmp")])
        if path:
            self.cover_path.set(path)

    def browse_output(self):
        path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Images", "*.png")])
        if path:
            self.output_path.set(path)

    def encode(self):
        cover = self.cover_path.get()
        out = self.output_path.get()
        password = self.password.get()
        message = self.msg_text.get("1.0", tk.END).strip()

        if not cover or not out or not password or not message:
            messagebox.showwarning("Missing Data", "Please fill all fields!")
            return
        try:
            encode_image(cover, out, message, password)
            messagebox.showinfo("Success", "Message hidden successfully!")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decode(self):
        stego = filedialog.askopenfilename(filetypes=[("PNG/BMP Images", "*.png;*.bmp")])
        password = self.password.get()
        if not stego or not password:
            messagebox.showwarning("Missing Data", "Please select a stego image and enter the password!")
            return
        try:
            msg = decode_image(stego, password)
            messagebox.showinfo("Hidden Message", msg)
        except Exception as e:
            messagebox.showerror("Error", str(e))

# ---------------------- MAIN ---------------------- #
if __name__ == "__main__":
    root = tk.Tk()
    app = StegoApp(root)
    root.mainloop()

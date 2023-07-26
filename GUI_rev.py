# imported necessary library
import tkinter
import io
import cv2
import os
import math
import hashlib
import numpy as np
import random
import tkinter as tk
import tkinter.messagebox as mbox
import matplotlib.pyplot as plt
from scipy.stats import entropy
from sewar.full_ref import mse
from tkinter import *
from tkinter import ttk
from tkinter import filedialog
from PIL import ImageTk
from PIL import Image
from base64 import b64encode, b64decode
from Crypto.Cipher import ChaCha20
from cv2 import *

def encrypt(plaintext, secret):
    cipher = ChaCha20.new(key=secret)
    ciphertext = cipher.nonce + cipher.encrypt(plaintext)
    return ciphertext

def decrypt(ciphertext, secret):
    msg_nonce = ciphertext[:8]
    ciphertext = ciphertext[8:]
    cipher = ChaCha20.new(key=secret, nonce=msg_nonce)
    decrypted_plaintext = cipher.decrypt(ciphertext)
    return decrypted_plaintext

# def bytes_to_bits(bits):
#     # Split the bit string into chunks of 8 bits
#     bit_chunks = [bits[i:i+8] for i in range(0, len(bits), 8)]

#     # Convert each chunk to a byte value
#     byte_data = bytes(int(chunk, 2) for chunk in bit_chunks)

#     return byte_data


def plot_hist(hist, num_bins=128):
    plt.hist(hist, density=1, bins=num_bins)
    plt.show()

def calculate_entropy(hist):
    prob_dist = hist / hist.sum()
    image_entropy = entropy(prob_dist, base=2)
    return image_entropy

def plot_hist(hist, num_bins=128):
    plt.hist(hist, density=1, bins=num_bins)
    plt.show()

def calculate_entropy(hist):
    prob_dist = hist / hist.sum()
    image_entropy = entropy(prob_dist, base=2)
    return image_entropy

def get_hist_for_entropy(image_path, num_bins=128):
    # Read the image
    image = cv2.imread(image_path)
    gray_image = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

    # Calculate histogram
    hist, _ = np.histogram(gray_image.ravel(), bins=num_bins, range=(0, num_bins))

    return hist

def get_mse_psnr(ori_path, decrypt_path):
    ori = cv2.imread(ori_path)
    decr = cv2.imread(decrypt_path)

    if (ori.shape != decr.shape):
        return "",""
    
    err_mse = mse(ori, decr)
    err_psnr = cv2.PSNR(ori, decr)

    return err_mse, err_psnr

# UI class
class application(tk.Tk):
    def __init__(window):
        super().__init__()
        
        #created main window
        window.geometry("1000x700")
        window.title("Image Encryption Decryption")

        window.image_path = tk.StringVar()
        window.encrypted_image_path = tk.StringVar()
        window.decrypted_image_path = tk.StringVar()
        window.secret_string = tk.StringVar()
        window.secret_key = tk.StringVar()
        window.img_width = tk.IntVar()
        window.img_height = tk.IntVar()
        window.create_widget()

    def show_original_histogram(window):
        if window.image_path.get():
            hist = get_hist_for_entropy(window.image_path.get())
            # print(window.image_path.get())
            plot_hist(hist)

    def show_decrypted_histogram(window):
        if window.decrypted_image_path.get():
            hist = get_hist_for_entropy(window.decrypted_image_path.get())
            # print(window.decrypted_image_path.get())
            plot_hist(hist)
    
    def show_encrypted_histogram(window):
        if window.decrypted_image_path.get():
            hist = get_hist_for_entropy(window.encrypted_image_path.get())
            # print(window.decrypted_image_path.get())
            plot_hist(hist)
    
    def update_entropy_labels(window, original_entropy, encrypted_entropy):
        window.ori_entropy_label.config(text="Original Image Entropy: " + str(original_entropy))
        window.en_entropy_label.config(text="Encrypted Image Entropy: " + str(encrypted_entropy))

    def update_mse_psnr_label(window, mse, psnr):
        window.mse_psnr_label.config(text="MSE: " + str(mse) + "  PSNR: " + str(psnr))

    def calc_npcr_uaci(self, img_ori_path, img_enc_path):

        image_ori = Image.open(img_ori_path).convert("RGB")
        image_enc = Image.open(img_enc_path).convert("RGB")

        array_ori = np.array(image_ori)
        array_enc = np.array(image_enc)

        #npcr
        total_pixels = array_ori.size
        differing_pixels = np.sum(array_ori != array_enc)
        npcr = (differing_pixels / total_pixels) * 100

        #uaci
        intensity_diff = np.abs(array_ori - array_enc)
        total = (255 * total_pixels)
        uaci = (np.sum(intensity_diff) / total) * 100

        self.npcr_uaci_label.config(text="NPCR: " + str(npcr) + " UACI: " + str(uaci))

    # def calc_uaci(self, img_ori_path, img_enc_path):

    #     image_ori = Image.open(img_ori_path).convert("RGB")
    #     image_enc = Image.open(img_enc_path).convert("RGB")

    #     ori_array = np.array(image_ori)
    #     enc_array = np.array(image_enc)

    #     intensity_diff = np.abs(ori_array - enc_array)

    #     uaci = np.mean(intensity_diff)

    def create_widget(window):
        #frame 1
        frame1 = tkinter.Frame(window)
        frame1.pack(pady=30)

        start1 = tk.Label(frame1, text = "Image Encryption Decryption", font=("Arial", 30), fg="black") # same way bg
        start1.pack()

        #frame 2
        frame2 = tkinter.Frame(window)
        frame2.pack()

        label_image_path = tk.Label(frame2, text="image path :")
        label_image_path.grid(row=0, column=0, pady=5)
        window.entry_image_path = tk.Entry(frame2, textvariable=window.image_path ,state="readonly", width=50)
        window.entry_image_path.grid(row=0, column=1, padx = 10)
        bt_open_image = tk.Button(frame2, text="  Open  ", command=window.open_image,borderwidth=3, relief="raised")
        bt_open_image.grid(row=0, column=2 )

        label_password = tk.Label(frame2, text="password :" )
        label_password.grid(row=1, column=0)
        entry_password = tk.Entry(frame2, textvariable=window.secret_string, state="normal", width=50)
        entry_password.grid(row=1, column=1)

        # bt_open_enimage = tk.Button(frame2, text="Open en image", command=window.open_enimage, borderwidth=3, relief="raised")
        # bt_open_enimage.grid(row=2, column=1, pady=5)

        #frame 3
        frame3 = tkinter.Frame(window)
        frame3.pack()

        window.ori_image_label = tk.Label(frame3, text="Opened Image")
        window.ori_image_label.grid(row=0, column=0, pady=10)
        ori_image_label1 = tk.Label(frame3, text="Opened Image")
        ori_image_label1.grid(row=1, column=0)

        window.encrypted_image_label = tk.Label(frame3, text="Encrypted Image")
        window.encrypted_image_label.grid(row=0, column=1, pady=10)
        encrypted_image_label1 = tk.Label(frame3, text="Encrypted Image")
        encrypted_image_label1.grid(row=1, column=1)

        window.decrypted_image_label = tk.Label(frame3, text="Decrypted Image")
        window.decrypted_image_label.grid(row=0, column=2, pady=10)
        decrypted_image_label1 = tk.Label(frame3, text="Decrypted Image")
        decrypted_image_label1.grid(row=1, column=2)

        #image label
        image0 = Image.open("openedimage.png")
        resize_image0 = image0.resize((250, 250), Image.ANTIALIAS)
        converted_image0 = ImageTk.PhotoImage(resize_image0)
        window.ori_image_label.config(image=converted_image0)
        window.ori_image_label.image = converted_image0

        image1 = Image.open("resultimage.png")
        resize_image1 = image1.resize((250, 250), Image.ANTIALIAS)
        converted_image1 = ImageTk.PhotoImage(resize_image1)
        window.encrypted_image_label.config(image=converted_image1)
        window.encrypted_image_label.image = converted_image1

        image2 = Image.open("result2image.png")
        resize_image2 = image2.resize((250, 250), Image.ANTIALIAS)
        converted_image2 = ImageTk.PhotoImage(resize_image2)
        window.decrypted_image_label.config(image=converted_image2)
        window.decrypted_image_label.image = converted_image2

        #button
        window.bt_encrypt = tk.Button(frame3, text="encrypt", command=window.encrypt_image, borderwidth=3, relief="raised")
        window.bt_encrypt.grid(row=2, column=1, padx=10, pady=10)
        window.bt_decrypt = tk.Button(frame3, text="decrypt", command=window.decrypt_image, borderwidth=3, relief="raised")
        window.bt_decrypt.grid(row=2, column=2, padx=10)

        #frame 5
        frame5 = tkinter.Frame(window)
        frame5.pack()

        bt_ori_histogram = tk.Button(frame5, text="ori image \n histogram",command=window.show_original_histogram, borderwidth=3, relief="raised")
        bt_ori_histogram.grid(row=0, column=0)
        bt_de_histogram = tk.Button(frame5, text="encrypted \n histogram", command=window.show_encrypted_histogram, borderwidth=3, relief="raised")
        bt_de_histogram.grid(row=1, column=0, padx=10, pady=10)
        bt_de_histogram = tk.Button(frame5, text="decrypted \n histogram", command=window.show_decrypted_histogram, borderwidth=3, relief="raised")
        bt_de_histogram.grid(row=2, column=0)

        window.ori_entropy_label = tk.Label(frame5, text="original image entropy :")
        window.ori_entropy_label.grid(row=0, column=1, pady=10)
        window.en_entropy_label = tk.Label(frame5, text="encrypted image entropy :")
        window.en_entropy_label.grid(row=1, column=1, pady=10)
        window.mse_psnr_label = tk.Label(frame5, text="MSE & PSNR :")
        window.mse_psnr_label.grid(row=2, column=1, pady=10)
        window.npcr_uaci_label = tk.Label(frame5, text="NPCR & UACI")
        window.npcr_uaci_label.grid(row=3, column=1, pady=10)

    def open_image(window):
        image_path = filedialog.askopenfilename(title='Buka Gambar')
        if image_path:
            try:
                image = Image.open(image_path)

                # get image size
                window.img_width, window.img_height = image.size
                window.image_path.set(image_path)

                # Clear
                window.ori_entropy_label.config(text="Original Image Entropy: " )
                window.en_entropy_label.config(text="Encrypted Image Entropy: " )
                window.mse_psnr_label.config(text="MSE & PSNR:")
                window.npcr_uaci_label.config(text="NPCR & UACI")
            except Exception as e:
                mbox.showerror("Error", str(e))

            ori_image = Image.open(image_path)

            resize_image = ori_image.resize((250, 250), Image.ANTIALIAS)
            
            converted_image = ImageTk.PhotoImage(resize_image)
            
            window.ori_image_label.config(image=converted_image)
            window.ori_image_label.image = converted_image
        else:
            mbox.showinfo("Error", "Please provide an image path.")

    def encrypt_image(window):
        image_path = window.image_path.get()
        if image_path:
            try:
                #read image
                img = Image.open(image_path).convert("RGB")

                # get pixel
                pixel_data = list(img.getdata())

                # Extract the RGB channel values
                encrypt_bytes = bytearray()
                for pixel in pixel_data:
                    for value in pixel:
                        encrypt_bytes.append(value)
                # print(len(encrypt_bytes))

                secret_key = hashlib.sha256(window.secret_string.get().encode()).digest()[:32]
                cyphertext = encrypt(encrypt_bytes, secret_key)
                # print(len(cyphertext))

                # Create a new image with PIL
                img = Image.new('RGB', (window.img_width, window.img_height))

                # Set the pixel values
                img.frombytes(bytes(cyphertext))

                # Save the encrypted image
                encrypted_image_path = filedialog.asksaveasfilename(defaultextension=".png")
                if encrypted_image_path:
                    img.save(encrypted_image_path)
                    window.encrypted_image_path.set(encrypted_image_path)
                    mbox.showinfo("Success", "Image encryption successful!")

                    # Display encrypted image
                    original_img = Image.open(encrypted_image_path)
                    # Resize the image to 50x50
                    resized_img = original_img.resize((250, 250), Image.ANTIALIAS)

                    # Convert the resized image to PhotoImage
                    tk_img = ImageTk.PhotoImage(resized_img)

                    # Configure the label to display the resized image
                    window.encrypted_image_label.config(image=tk_img)
                    window.encrypted_image_label.image = tk_img
                else:
                    mbox.showinfo("Error", "Invalid save path.")
            except Exception as e:
                mbox.showerror("Error", str(e))

        else:
            mbox.showinfo("Error", "Open Image First..!!!")

    def decrypt_image(window):
        encrypted_image_path = window.encrypted_image_path.get()
        if encrypted_image_path:
            try:
                image_de = Image.open(encrypted_image_path).convert("RGB")

                # Retrieve the pixel values
                pixel_data_de = list(image_de.getdata())

                # Extract the RGB channel values
                byte_data_de = bytearray()
                for pixel in pixel_data_de:
                    for value in pixel:
                        byte_data_de.append(value)

                # Convert byte data to bits
                bytes_to_decrypt = byte_data_de + b'\0' * 8

                secret_key = hashlib.sha256(window.secret_string.get().encode()).digest()[:32]
                decrypted_bytes = decrypt(bytes_to_decrypt, secret_key)

                # Create a PIL Image object from the decrypted image data
                decrypted_image = Image.new('RGB', (window.img_width, window.img_height))
                decrypted_image.frombytes(decrypted_bytes)

                # Save the decrypted image
                decrypted_image_path = filedialog.asksaveasfilename(defaultextension=".png")
                if decrypted_image_path:
                    decrypted_image.save(decrypted_image_path)
                    window.decrypted_image_path.set(decrypted_image_path)
                    mbox.showinfo("Success", "Image decryption successful!")
                    # Display decrypted image
                    original_img = Image.open(decrypted_image_path)
                    # Resize the image to 50x50
                    resized_img = original_img.resize((250, 250), Image.ANTIALIAS)
                    # Convert the resized image to PhotoImage
                    tk_img = ImageTk.PhotoImage(resized_img)
                    # Configure the label to display the resized image
                    window.decrypted_image_label.config(image=tk_img)
                    window.decrypted_image_label.image = tk_img

                    # Calculate histogram and entropy of the original image
                    ori_hist = get_hist_for_entropy(window.image_path.get())
                    ori_entropy = calculate_entropy(ori_hist)

                    # Calculate histogram and entropy of the decrypted image
                    decrypted_hist = get_hist_for_entropy(decrypted_image_path)
                    decrypted_entropy = calculate_entropy(decrypted_hist)
                    
                    # Update the entropy labels
                    window.update_entropy_labels(ori_entropy, decrypted_entropy)

                    # Calculate MSE and PSNR
                    mse, psnr = get_mse_psnr(window.image_path.get(), decrypted_image_path)

                    # Calculate npcr
                    window.calc_npcr_uaci(window.image_path.get(), window.encrypted_image_path.get())

                    # Update the MSE/PSNR label
                    window.update_mse_psnr_label(mse, psnr)

                else:
                    mbox.showinfo("Error", "Invalid save path.")
                
            except Exception as e:
                mbox.showerror("Error", str(e))
        else:
            mbox.showinfo("Error", "Please provide the encrypted image path.")
        
#loop UI
# function created for exiting
def exit_win():
    if mbox.askokcancel("Exit", "Do you want to exit?"):
        app.destroy()

app = application()
app.protocol("WM_DELETE_WINDOW", exit_win)
app.mainloop()
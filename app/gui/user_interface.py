import app.core.project_constants as const
from app.core.certificate_authority import CertificateAuthority
from app.core.certificate_user import CertificateUser
from app.core.certificate_io import CertificateIO
from app.signatures.pdf_signature import PDFSignature
from app.signatures.file_signature import FileSignature
from app.signatures.png_signature import PNGSignature
from app.signatures.mp3_signature import MP3Signature

import tkinter as tk
import ttkbootstrap as ttk
from tkinter import filedialog
from datetime import datetime, timedelta
from os import path as os_path
from pathlib import Path as PathLib


def file_get_extension(file_path):
    # Get file extension from path
    pathLib = PathLib(file_path)
    return pathLib.suffix

def file_add_signed_suffix(file_path, path_suffix=None):
    # Create a path for new file
    pathLib = PathLib(file_path)
    if path_suffix is None:
        return pathLib.with_name(pathLib.stem + '_signed' + pathLib.suffix)
    return pathLib.with_name(pathLib.stem + '_signed' + path_suffix)

def file_path_valid(file_path):
    if len(file_path) == 0:
        return True
    if os_path and os_path.exists(file_path):
        return True
    return False

def gui_select_file_prompt(entry):
    # Get system prompt for file choice
    HOME_DIRECTORY = os_path.expanduser("~")
    file = filedialog.askopenfilename(initialdir=HOME_DIRECTORY, title="Select a file")
    entry.delete(0, 'end')
    entry.insert(0, file)

def gui_window_output_write(frame, message, bootstyle, font=12, deletePrevious=False):
    if deletePrevious:
        for widget in frame.winfo_children():
            widget.destroy()
    ttk.Label(frame, text=message, font=("Consolas", font, "bold"), bootstyle=bootstyle).pack(pady=10)

def gui_create_certificate_user(user, cert_auth, file_user_name, file_user_password, user_path):
    # Create user instance
    user.generate_keys_rsa()
    user.certificate_signing_request(
        const.USER_COUNTRY,
        const.USER_STATE_OR_PROVINCE,
        const.USER_LOCALITY,
        file_user_name,
        file_user_name
    )
    cert_auth.issue_certificate(
        user_cert_instance=user,
        not_valid_before=const.USER_NOT_VALID_BEFORE,
        not_valid_after=const.USER_NOT_VALID_AFTER,
        path=user_path, 
        file_name=file_user_name + const.USER_CERT_SUFFIX
    )
    user.file_save_private_key(user_path, file_user_name + const.USER_KEY_SUFFIX, file_user_password)

def gui_create_certificate_authority(cert_auth):
    # Create CA
    cert_auth.generate_keys_rsa()
    cert_auth.generate_certificate_authority(
        const.CA_COUNTRY,
        const.CA_STATE_OR_PROVINCE,
        const.CA_LOCALITY,
        const.CA_ORGANIZATION,
        const.CA_COMMON_NAME,
        const.CA_NOT_VALID_BEFORE,
        const.CA_NOT_VALID_AFTER
    )
    # Save CA certificate and private key to files
    cert_auth.file_save_private_key(const.CA_FILE_SAVE_PATH, const.CA_KEY_FILE_NAME, const.CA_KEY_FILE_PASSWORD)
    cert_auth.file_save_certificate(const.CA_FILE_SAVE_PATH, const.CA_CERT_FILE_NAME)
    return cert_auth

def gui_init_certificate_authority(cert_auth):
    # Create CA if does not exist, otherwise load from a file and check validity (does not warn user if renewed!)
    if (
        not cert_auth.file_load_certificate(const.CA_FILE_SAVE_PATH, const.CA_CERT_FILE_NAME)
        or not cert_auth.file_load_private_key(const.CA_FILE_SAVE_PATH, const.CA_KEY_FILE_NAME, const.CA_KEY_FILE_PASSWORD)
        or not cert_auth.verify_certificate(cert_auth.certificate)
    ):
        gui_create_certificate_authority(cert_auth)

def gui_window_start(cert_auth):
    # App main interface
    window = tk.Tk()
    window.title("Digital Signage App")
    window.geometry("1000x825")
    window.resizable(False, False)

    file_frame = ttk.Frame(window)
    file_frame.place(x=0, y=0, width=1000, height=800)

    # RESULT FRAME
    output_frame = ttk.LabelFrame(file_frame, text='OUTPUT')
    output_frame.place(x=100, y=50, width=800, height=300)

    # USERNAME
    ttk.Label(file_frame, text='USERNAME', font=("Consolas", 12, "bold"), bootstyle='primary').place(x=250, y=370)
    username_entry = ttk.Entry(file_frame)
    username_entry.place(x=250, y=400, width=280, height=40)

    # PASSWORD
    ttk.Label(file_frame, text='PASSWORD', font=("Consolas", 12, "bold"), bootstyle='primary').place(x=540, y=370)
    password_entry = ttk.Entry(file_frame, show="*")
    password_entry.place(x=540, y=400, width=270, height=40)

    # FILE TO BE SIGNED
    ttk.Label(file_frame, text='FILE TO BE SIGNED', font=("Consolas", 12, "bold"), bootstyle='primary').place(x=250, y=470)
    file_to_be_signed_entry = ttk.Entry(file_frame)
    file_to_be_signed_entry.place(x=250, y=500, width=450, height=40)
    ttk.Button(file_frame, text='VIEW FILE', command=lambda: gui_select_file_prompt(file_to_be_signed_entry), bootstyle='info-outline').place(x=710, y=500, width=100, height=40)

    # FILE TO BE VERIFIED
    ttk.Label(file_frame, text='FILE TO BE VERIFIED', font=("Consolas", 12, "bold"), bootstyle='primary').place(x=250, y=560)
    file_to_be_verified = ttk.Entry(file_frame)
    file_to_be_verified.place(x=250, y=590, width=450, height=40)
    ttk.Button(file_frame, text='VIEW FILE', command=lambda: gui_select_file_prompt(file_to_be_verified), bootstyle='info-outline').place(x=710, y=590, width=100, height=40)

    # FILE WITH SEPARATE SIGNATURE
    ttk.Label(file_frame, text='FILE WITH SEPARATE SIGNATURE (.sig)', font=("Consolas", 12, "bold"), bootstyle='primary').place(x=250, y=650)
    file_with_separate_signature = ttk.Entry(file_frame)
    file_with_separate_signature.place(x=250, y=680, width=450, height=40)
    ttk.Button(file_frame, text='VIEW FILE', command=lambda: gui_select_file_prompt(file_with_separate_signature), bootstyle='info-outline').place(x=710, y=680, width=100, height=40)

    # SUBMIT Button
    ttk.Button(file_frame, text='SUBMIT', command=lambda: handle_on_submit(cert_auth, output_frame, username_entry, password_entry, file_to_be_signed_entry, file_to_be_verified, file_with_separate_signature)).place(x=450, y=750, width=100, height=40)

    window.mainloop()

def handle_file_operation(user, output_frame, file_path_for_signage, file_path_to_verify_signature, file_path_to_verify):
    # Choose a correct operation, depending on textfield length
    if (len(file_path_for_signage) > 0):
        handle_file_signage(
            user=user, 
            output_frame=output_frame, 
            file_path_for_signage=file_path_for_signage
        )
    elif (len(file_path_to_verify) > 0):
        handle_file_verification(
            user=user, 
            output_frame=output_frame, 
            file_path_to_verify=file_path_to_verify, 
            file_path_to_verify_signature=file_path_to_verify_signature
        )

def handle_file_signage(user, output_frame, file_path_for_signage):
    file_extension = file_get_extension(file_path_for_signage)
    new_file_path = file_add_signed_suffix(file_path_for_signage)
    
    match(file_extension):
        case ".pdf":
            try:
                pdf = PDFSignature(user.private_key, file_path_for_signage)
                pdf.normalize_pdf(const.FILE_TEMP_DIRECTORY)
                pdf.create_signature_pdf(new_file_path)

                gui_window_output_write(output_frame, "PDF has been signed successfully! Location:", bootstyle='success', font=12, deletePrevious=True)
                gui_window_output_write(output_frame, new_file_path, bootstyle='success', font=8)
            except Exception as e:
                gui_window_output_write(output_frame, "There has been an error while creating signature for this PDF!", bootstyle='danger', font=12, deletePrevious=True)

        case ".png":
            try:
                png = PNGSignature(user.private_key, file_path_for_signage)
                png.normalize_png(const.FILE_TEMP_DIRECTORY)
                png.create_signature_png(new_file_path)

                gui_window_output_write(output_frame, "PNG has been signed successfully! Location:", bootstyle='success', font=12, deletePrevious=True)
                gui_window_output_write(output_frame, new_file_path, bootstyle='success', font=8)
            except Exception as e:
                gui_window_output_write(output_frame, "There has been an error while creating signature for this PNG!", bootstyle='danger', font=12, deletePrevious=True)

        case ".mp3":
            try:
                mp3 = MP3Signature(user.private_key, file_path_for_signage)
                mp3.normalize_mp3(const.FILE_TEMP_DIRECTORY)
                mp3.create_signature_mp3(new_file_path)

                gui_window_output_write(output_frame, "MP3 has been signed successfully! Location:", bootstyle='success', font=12, deletePrevious=True)
                gui_window_output_write(output_frame, new_file_path, bootstyle='success', font=8)
            except Exception as e:
                gui_window_output_write(output_frame, "There has been an error while creating signature for this MP3!", bootstyle='danger', font=12, deletePrevious=True)

        case _:
            try:
                new_file_path = file_add_signed_suffix(file_path_for_signage, const.FILE_UNKNOWN_SIGNAGE_FILETYPE_EXTENSION)
                file = FileSignature(user.private_key, file_path_for_signage)
                file.create_signature_file(new_file_path)

                gui_window_output_write(output_frame, "File signature has been created successfully! Location:", bootstyle='success', font=12, deletePrevious=True)
                gui_window_output_write(output_frame, new_file_path, bootstyle='success', font=8)
            except Exception as e:
                gui_window_output_write(output_frame, "There has been an error while creating signature for this file!", bootstyle='danger', font=12, deletePrevious=True)

def handle_file_verification(user, output_frame, file_path_to_verify, file_path_to_verify_signature):
    file_extension = file_get_extension(file_path_to_verify)

    match(file_extension):
        case ".pdf":
            try:
                pdf = PDFSignature(user.private_key, file_path_to_verify)
                signature = pdf.read_signature_pdf(pdf.file_path)
                pdf.normalize_pdf(const.FILE_TEMP_DIRECTORY)
                pdf.remove_signature_pdf(file_path_to_verify, pdf.file_path)
                new_pdf = PDFSignature(user.private_key, pdf.file_path)

                if new_pdf.compare_signature(signature):
                    gui_window_output_write(output_frame, "PDF signature has been validated successfully!", "success", deletePrevious=True)
                else:
                    gui_window_output_write(output_frame, "PDF signature is incorrect! File has been changed!", "danger", deletePrevious=True)
            except Exception as e:
                gui_window_output_write(output_frame, "PDF has been corrupted! Unable to validate the file!", "danger", deletePrevious=True)

        case ".png":
            try:
                png = PNGSignature(user.private_key, file_path_to_verify)
                signature = png.read_signature_png(png.file_path)
                png.normalize_png(const.FILE_TEMP_DIRECTORY)
                png.remove_signature_png(file_path_to_verify, png.file_path)
                new_png = PNGSignature(user.private_key, png.file_path)

                if new_png.compare_signature(signature):
                    gui_window_output_write(output_frame, "PNG signature has been validated successfully!", "success", deletePrevious=True)
                else:
                    gui_window_output_write(output_frame, "PNG signature is incorrect! File has been changed!", "danger", deletePrevious=True)
            except Exception as e:
                gui_window_output_write(output_frame, "PNG has been corrupted! Unable to validate the file!", "danger", deletePrevious=True)

        case ".mp3":
            try:
                mp3 = MP3Signature(user.private_key, file_path_to_verify)
                signature = mp3.read_signature_mp3(mp3.file_path)
                mp3.normalize_mp3(const.FILE_TEMP_DIRECTORY)
                mp3.remove_signature_mp3(file_path_to_verify, mp3.file_path)
                new_mp3 = MP3Signature(user.private_key, mp3.file_path)

                if new_mp3.compare_signature(signature):
                    gui_window_output_write(output_frame, "MP3 signature has been validated successfully!", "success", deletePrevious=True)
                else:
                    gui_window_output_write(output_frame, "MP3 signature is incorrect! File has been changed!", "danger", deletePrevious=True)
            except Exception as e:
                gui_window_output_write(output_frame, "MP3 has been corrupted! Unable to validate the file!", "danger", deletePrevious=True)

        case _:
            if not file_path_valid(file_path_to_verify_signature) or len(file_path_to_verify_signature) == 0:
                gui_window_output_write(output_frame, "Signature file not loaded!", "danger", deletePrevious=True)
                return
            try:
                file = FileSignature(user.private_key, file_path_to_verify)
                signature = file.read_signature_file(file_path_to_verify_signature)

                if file.compare_signature(signature):
                    gui_window_output_write(output_frame, "File signature has been validated successfully!", "success", deletePrevious=True)
                else:
                    gui_window_output_write(output_frame, "File signature is incorrect! File has been changed!", "danger", deletePrevious=True)
            except Exception as e:
                gui_window_output_write(output_frame, "Signature file has been corrupted! Unable to validate the file!", "danger", deletePrevious=True)

def handle_on_submit(cert_auth, output_frame, username_entry, password_entry, file_to_be_signed_entry, file_to_be_verified, file_with_separate_signature):
    file_user_name = username_entry.get()
    file_user_password = password_entry.get()
    file_path_for_signage = file_to_be_signed_entry.get()
    file_path_to_verify = file_to_be_verified.get()
    file_path_to_verify_signature = file_with_separate_signature.get()

    if file_user_password == "":
        gui_window_output_write(output_frame, "Username or password is missing!", "danger", deletePrevious=True)
        return

    user = CertificateUser()
    user_path = os_path.join(const.USER_FILE_SAVE_PATH, file_user_name)
    
    try:
        cert_loaded = user.file_load_certificate(user_path, file_user_name + const.USER_CERT_SUFFIX)
        key_loaded = user.file_load_private_key(user_path, file_user_name + const.USER_KEY_SUFFIX, file_user_password)

        if not cert_loaded or not key_loaded:
            gui_create_certificate_user(
                user=user,
                cert_auth=cert_auth,
                file_user_name=file_user_name,
                file_user_password=file_user_password,
                user_path=user_path
            )
            gui_window_output_write(output_frame, "Certificate and private key created successfully!", "success", deletePrevious=True)

        elif not cert_auth.verify_certificate(user.certificate):
            gui_window_output_write(output_frame, "Certificate is expired!", "danger", deletePrevious=True)
            gui_window_output_write(output_frame, "Files signed by this certificate can no longer be validated!", "danger")
            gui_create_certificate_user(
                user=user,
                cert_auth=cert_auth,
                file_user_name=file_user_name,
                file_user_password=file_user_password,
                user_path=user_path
            )
            gui_window_output_write(output_frame, "Certificate and private key renewed successfully!", "success")
        else:
            gui_window_output_write(output_frame, "Certificate and private key loaded successfully!", "success", deletePrevious=True)

    except ValueError as e:
        gui_window_output_write(output_frame, "Incorrect password! Please try again.", "danger", deletePrevious=True)
        return

    try:
        if not file_path_valid(file_path_for_signage):
            gui_window_output_write(output_frame, "Incorrect file for signage path!", "danger", deletePrevious=True)
            return

        if not file_path_valid(file_path_to_verify):
            gui_window_output_write(output_frame, "Incorrect file to verify path!", "danger", deletePrevious=True)
            return

        if not file_path_valid(file_path_to_verify_signature):
            gui_window_output_write(output_frame, "Incorrect signature file path!", "danger", deletePrevious=True)
            return

        handle_file_operation(
            user=user,
            output_frame=output_frame,
            file_path_for_signage=file_path_for_signage,
            file_path_to_verify=file_path_to_verify,
            file_path_to_verify_signature=file_path_to_verify_signature,
        )

    except Exception as e:
        gui_window_output_write(output_frame, f"There has been an unknown error while handling a file.", "danger", deletePrevious=True)
        return

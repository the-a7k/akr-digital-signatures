import app.core.project_constants as const
from app.core.certificate_authority import CertificateAuthority
from app.signatures.file_signature import FileSignature
from app.gui.user_interface import gui_init_certificate_authority, gui_window_start


if __name__ == "__main__":
    cert_auth = CertificateAuthority()
    gui_init_certificate_authority(cert_auth)
    gui_window_start(cert_auth)
    FileSignature.directory_remove(const.FILE_TEMP_DIRECTORY)
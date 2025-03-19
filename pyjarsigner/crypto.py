"""
Cryptography-related functions for handling JAR signature block files.
"""

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import (rsa, dsa, ec, padding)
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.openssl import backend as openssl_backend
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

class CannotFindKeyTypeError(Exception):
    pass

class SignatureBlockVerificationError(Exception):
    pass

def private_key_type(key_file):
    with open(key_file, 'rb') as f:
        key_data = f.read()
    try:
        key = serialization.load_pem_private_key(
            key_data, password=None, backend=default_backend()
        )
    except ValueError:
        raise CannotFindKeyTypeError()

    if isinstance(key, rsa.RSAPrivateKey):
        return "RSA"
    elif isinstance(key, dsa.DSAPrivateKey):
        return "DSA"
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        return "EC"
    else:
        raise CannotFindKeyTypeError()

def create_signature_block(openssl_digest, certificate, private_key,
                           extra_certs, data):
    """
    Produces a signature block for the data using PyCA/cryptography.

    :param openssl_digest: Digest algorithm (e.g., 'sha256')
    :param certificate: Path to the certificate (PEM)
    :param private_key: Path to the private key (PEM)
    :param extra_certs: List of paths to additional certificates (PEM)
    :param data: Data to be signed
    :return: DER-encoded PKCS7 signature
    """
    # Load private key
    with open(private_key, 'rb') as f:
        key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

    # Load certificate
    with open(certificate, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())

    # Load extra certificates
    extra_certs_objs = []
    for cert_file in extra_certs or []:
        with open(cert_file, 'rb') as f:
            extra_certs_objs.append(
                x509.load_pem_x509_certificate(f.read(), default_backend())
            )

    # Map digest algorithm
    hash_algorithm = {
        'sha1': hashes.SHA1,
        'sha256': hashes.SHA256,
        'sha384': hashes.SHA384,
        'sha512': hashes.SHA512,
    }[openssl_digest.lower()]()

    # Configure PKCS7 options
    options = [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.NoAttributes]

    # Build and sign PKCS7 structure
    builder = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(data.encode())
        .add_signer(cert, key, hash_algorithm)
    )
    if extra_certs_objs:
        builder = builder.add_certificates(extra_certs_objs)

    return builder.sign(serialization.Encoding.DER, options)


def verify_signature_block(certificate_file, content, signature):
    """Verifies PKCS7 signature using OpenSSL's low-level implementation."""
    backend = default_backend()
    openssl = openssl_backend

    # Load trusted certificate
    with open(certificate_file, 'rb') as f:
        trusted_cert = x509.load_pem_x509_certificate(f.read(), backend)
    
    # Create X509_STORE and add trusted certificate
    store = openssl._lib.X509_STORE_new()
    openssl.openssl_assert(store != openssl._ffi.NULL)
    ossl_cert = openssl._cert2ossl(trusted_cert)
    res = openssl._lib.X509_STORE_add_cert(store, ossl_cert)
    openssl.openssl_assert(res == 1)

    # Load PKCS7 structure from DER
    bio = openssl._bytes_to_bio(signature)
    pkcs7_ptr = openssl._lib.d2i_PKCS7_bio(bio.bio, openssl._ffi.NULL)
    if pkcs7_ptr == openssl._ffi.NULL:
        raise SignatureBlockVerificationError("Invalid PKCS7 structure")

    # Verify the signature
    data_bio = openssl._bytes_to_bio(content.encode())
    flags = (
        openssl._lib.PKCS7_BINARY |
        openssl._lib.PKCS7_NOVERIFY |
        openssl._lib.PKCS7_NOCHAIN
    )
    result = openssl._lib.PKCS7_verify(
        pkcs7_ptr,
        openssl._ffi.NULL,  # No additional certificates
        store,
        data_bio.bio,
        openssl._ffi.NULL,  # No output BIO
        flags
    )

    if result != 1:
        error = openssl._consume_errors()
        raise SignatureBlockVerificationError(
            f"Verification failed: {openssl._errors_with_text(error)}"
        )

    return None

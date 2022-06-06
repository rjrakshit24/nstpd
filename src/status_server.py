from nstp_pb2 import *
import socket
import struct
import asyncio
import time
from nacl.bindings import \
    crypto_box_keypair, \
    crypto_sign_keypair, crypto_sign_ed25519ph_state, crypto_sign_ed25519ph_update, crypto_sign_ed25519ph_final_create, \
    crypto_kx_server_session_keys, crypto_sign_ed25519ph_final_verify
import coloredlogs
import logging

coloredlogs.install(level='DEBUG')

localIP     = "0.0.0.0"
localPort   = 1501
status_cert = Certificate()
status_cert.ParseFromString(open("status.crt", "rb").read())
status_key = PrivateKey()
status_key.ParseFromString(open("status.key", "rb").read())

def status_signing_state(state, status: CertificateStatus):
    crypto_sign_ed25519ph_update(state, status.certificate.value)
    if status.certificate.algorithm == HashAlgorithm.IDENTITY:
        crypto_sign_ed25519ph_update(state, struct.pack("B", 0))
    elif status.certificate.algorithm == HashAlgorithm.SHA256:
        crypto_sign_ed25519ph_update(state, struct.pack("B", 1))
    elif status.certificate.algorithm == HashAlgorithm.SHA512:
        crypto_sign_ed25519ph_update(state, struct.pack("B", 2))
    if status.status == CertificateStatus.UNKNOWN:
        crypto_sign_ed25519ph_update(state, struct.pack("B", 0))
    elif status.status == CertificateStatus.VALID:
        crypto_sign_ed25519ph_update(state, struct.pack("B", 1))
    elif status.status == CertificateStatus.INVALID:
        crypto_sign_ed25519ph_update(state, struct.pack("B", 2))
    crypto_sign_ed25519ph_update(state, struct.pack(">Q", status.valid_from))
    crypto_sign_ed25519ph_update(state, struct.pack(">I", status.valid_length))
    state = certificate_signing_state(state, status.status_certificate, True)
    return state

def certificate_signing_state(state, cert: Certificate, include_signature: bool):
    for x in cert.subjects:
        crypto_sign_ed25519ph_update(state, x.encode())
    crypto_sign_ed25519ph_update(state, struct.pack(">Q", cert.valid_from))
    crypto_sign_ed25519ph_update(state, struct.pack(">I", cert.valid_length))
    for x in cert.usages:
        if x == CertificateUsage.CERTIFICATE_SIGNING:
            crypto_sign_ed25519ph_update(state, struct.pack("B", 0))
        elif x == CertificateUsage.CLIENT_AUTHENTICATION:
            crypto_sign_ed25519ph_update(state, struct.pack("B", 1))
        elif x == CertificateUsage.SERVER_AUTHENTICATION:
            crypto_sign_ed25519ph_update(state, struct.pack("B", 2))
        elif x == CertificateUsage.STATUS_SIGNING:
            crypto_sign_ed25519ph_update(state, struct.pack("B", 3))
    crypto_sign_ed25519ph_update(state, cert.encryption_public_key)
    crypto_sign_ed25519ph_update(state, cert.signing_public_key)
    if cert.HasField("issuer"):
        crypto_sign_ed25519ph_update(state, cert.issuer.value)
        if cert.issuer.algorithm == HashAlgorithm.IDENTITY:
            crypto_sign_ed25519ph_update(state, struct.pack("B", 0))
        elif cert.issuer.algorithm == HashAlgorithm.SHA256:
            crypto_sign_ed25519ph_update(state, struct.pack("B", 1))
        elif cert.issuer.algorithm == HashAlgorithm.SHA512:
            crypto_sign_ed25519ph_update(state, struct.pack("B", 2))
    if include_signature:
        crypto_sign_ed25519ph_update(state, cert.issuer_signature)
    return state

def getResponse(ocspRequest):
    status_response = CertificateStatusResponse()    
    status_response.certificate.CopyFrom(ocspRequest.certificate)
    status_response.status = CertificateStatus.VALID
    status_response.valid_from = int(time.time())
    status_response.valid_length = 60 * 60
    status_response.status_certificate.CopyFrom(status_cert)
    state = crypto_sign_ed25519ph_state()
    state = status_signing_state(state, status_response)
    status_response.status_signature = crypto_sign_ed25519ph_final_create(state, status_key.signing_private_key)
    print(status_response)
    # status_response = CertificateStatusResponse()
    # status_response.ParseFromString(open("server_status", "rb").read())
    return status_response.SerializeToString()

class EchoServerProtocol:
    def connection_made(self, transport):
        logging.info("New Connection Made")
        self.transport = transport

    def datagram_received(self, data, addr):
        ocspRequest = CertificateStatusRequest()
        ocspRequest.ParseFromString(data)
        logging.debug(ocspRequest)
        ocspResponse = getResponse(ocspRequest)
        self.transport.sendto(ocspResponse, addr)
        # logging.info(struct.pack(">H", len(ocspResponse)) + ocspResponse)
        logging.info("Datagram Sent")

async def run_server():
    logging.info("Starting server")
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(lambda: EchoServerProtocol(),local_addr=(localIP, localPort))
    try:
        await asyncio.sleep(3600)  # Serve for 1 hour.
    finally:
        transport.close()

asyncio.run(run_server())

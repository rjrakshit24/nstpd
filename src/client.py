import struct
import time
import hashlib
import asyncio
import sys
import tomlkit
import re
import socket
from typing import Optional
import logging
import coloredlogs
import traceback
from nacl.utils import random as nonceGenerator
from nacl.bindings import \
    crypto_box_keypair, \
    crypto_sign_keypair, crypto_sign_ed25519ph_state, crypto_sign_ed25519ph_update, crypto_sign_ed25519ph_final_create, \
    crypto_kx_client_session_keys, crypto_sign_ed25519ph_final_verify, crypto_secretbox, crypto_secretbox_open
from nacl.secret import SecretBox
from nstp_pb2 import *

from pathlib import Path
coloredlogs.install(level='DEBUG')

VALID_LENGTH_SEC = 60 * 60 * 24 * 14

class Settings:
    CAStore = CertificateStore()
    ServerCert = Certificate()
    ServerKey = PrivateKey()
    PinnedCertStore = PinnedCertificateStore()
    StatusServerResponse = None
    DataStore = "./internal/" #dict()
    Regexes = {
        'dns': re.compile("^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\\.)+[A-Za-z]{2,6}$|^localhost$"),
        'ipv4': re.compile("^(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))\.(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))\.(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))\.(\d|[1-9]\d|1\d\d|2([0-4]\d|5[0-5]))$"),
        'ipv6': re.compile("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")
    }

    @classmethod
    def setServerAddress(cls, addr: str):
        addr = addr.split(":")
        cls.ServerAddress = (addr[0], int(addr[1]))
    @classmethod
    def setStatusServerAddress(cls, addr: str):
        addr = addr.split(":")
        cls.StatusServerAddress = (addr[0], int(addr[1]))
    
    @classmethod
    def setStatusServerResponse(cls, response):
        cls.StatusServerResponse = response

    @classmethod
    def getStatusServerResponse(cls):
        return cls.StatusServerResponse

    @classmethod
    def storeData(cls, k: str, v: bytes, u: str):
        logging.info("Storing Data Function")
        logging.info(f"User: {u}, Key: {k}")
        Path(cls.DataStore + u).mkdir(parents=True, exist_ok=True)
        with open(cls.DataStore + u + "/" + k, "w+b") as f:
            f.write(v)
    
    @classmethod
    def loadData(cls, k: str, u: str):
        logging.info("Loading Data Function")
        logging.info(f"User: {u}, Key: {k}")
        if not Path(cls.DataStore + u + "/" + k).is_file():
            return b""
        with open(cls.DataStore + u + "/" + k, "rb") as f:
            return f.read()


def hash_certificate(h, cert: Certificate) -> bytes:
    for x in cert.subjects:
        h.update(x.encode())
    h.update(struct.pack(">Q", cert.valid_from))
    h.update(struct.pack(">I", cert.valid_length))
    for x in cert.usages:
        if x == CertificateUsage.CERTIFICATE_SIGNING:
            h.update(struct.pack("B", 0))
        elif x == CertificateUsage.CLIENT_AUTHENTICATION:
            h.update(struct.pack("B", 1))
        elif x == CertificateUsage.SERVER_AUTHENTICATION:
            h.update(struct.pack("B", 2))
        elif x == CertificateUsage.STATUS_SIGNING:
            h.update(struct.pack("B", 3))
        else:
            raise Exception("invalid usage")
    h.update(cert.encryption_public_key)
    h.update(cert.signing_public_key)

    if cert.HasField("issuer"):
        h.update(cert.issuer.value)
        if cert.issuer.algorithm == HashAlgorithm.SHA256:
            h.update(struct.pack("B", 1))
        elif cert.issuer.algorithm == HashAlgorithm.SHA512:
            h.update(struct.pack("B", 2))
        else:
            raise Exception("invalid issuer algorithm")

    h.update(cert.issuer_signature)
    return h.digest()

def hash_certificate_sha256(cert: Certificate) -> bytes:
    return hash_certificate(hashlib.sha256(), cert)

def hash_certificate_sha512(cert: Certificate) -> bytes:
    return hash_certificate(hashlib.sha512(), cert)

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

def create_certificate(subjects: 'list[str]',
                       valid_length: int,
                       usages: 'list[CertificateUsage]',
                       encryption_key: bytes,
                       signing_key: bytes,
                       issuer: Optional[CertificateHash],
                       issuer_signing_key: bytes) -> Certificate:
    cert = Certificate()
    for x in subjects:
        cert.subjects.append(x)
    cert.valid_from = int(time.time())
    cert.valid_length = valid_length
    for x in usages:
        cert.usages.append(x)
    cert.encryption_public_key = encryption_key
    cert.signing_public_key = signing_key
    if issuer is not None:
        cert.issuer.CopyFrom(issuer)
    state = crypto_sign_ed25519ph_state()
    state = certificate_signing_state(state, cert, False)
    cert.issuer_signature = crypto_sign_ed25519ph_final_create(state, issuer_signing_key)
    return cert

def create_private_key(cert, encryption_key, signing_key):
    key = PrivateKey()
    key.certificate.value = hash_certificate_sha512(cert)
    key.certificate.algorithm = HashAlgorithm.SHA512
    key.encryption_private_key = encryption_key
    key.signing_private_key = signing_key
    return key

def init_pki():
    e_pub_key, e_sec_key = crypto_box_keypair()
    s_pub_key, s_sec_key = crypto_sign_keypair()

    ca_cert = create_certificate(["CA"],
                                 VALID_LENGTH_SEC,
                                 [CertificateUsage.CERTIFICATE_SIGNING],
                                 e_pub_key,
                                 s_pub_key,
                                 None,
                                 s_sec_key)
    trust_store = CertificateStore()
    with open("ca.crt", "wb") as fd:
        fd.write(trust_store.SerializeToString())

    trust_store.certificates.append(ca_cert)
    with open("ca_store", "wb") as fd:
        fd.write(trust_store.SerializeToString())

    ca_key = create_private_key(ca_cert, e_sec_key, s_sec_key)
    with open("ca.key", "wb") as fd:
        fd.write(ca_key.SerializeToString())

    issuer_hash = CertificateHash()
    issuer_hash.value = hash_certificate_sha256(ca_cert)
    issuer_hash.algorithm = HashAlgorithm.SHA256

    e_pub_key, e_sec_key = crypto_box_keypair()
    s_pub_key, s_sec_key = crypto_sign_keypair()
    server_cert = create_certificate(["localhost", "10.110.156.254", "::1"],
                                     VALID_LENGTH_SEC,
                                     [CertificateUsage.SERVER_AUTHENTICATION],
                                     e_pub_key,
                                     s_pub_key,
                                     issuer_hash,
                                     ca_key.signing_private_key)
    with open("server.crt", "wb") as fd:
        fd.write(server_cert.SerializeToString())

    server_key = create_private_key(server_cert, e_sec_key, s_sec_key)
    with open("server.key", "wb") as fd:
        fd.write(server_key.SerializeToString())

    e_pub_key, e_sec_key = crypto_box_keypair()
    s_pub_key, s_sec_key = crypto_sign_keypair()
    client_cert = create_certificate(["mario"],
                                     VALID_LENGTH_SEC,
                                     [CertificateUsage.CLIENT_AUTHENTICATION],
                                     e_pub_key,
                                     s_pub_key,
                                     issuer_hash,
                                     ca_key.signing_private_key)
    with open("client.crt", "wb") as fd:
        fd.write(client_cert.SerializeToString())

    client_key = create_private_key(client_cert, e_sec_key, s_sec_key)
    with open("client.key", "wb") as fd:
        fd.write(client_key.SerializeToString())

    with open("pinned_certs", "wb") as fd:
        fd.write(PinnedCertificateStore().SerializeToString())

    e_pub_key, e_sec_key = crypto_box_keypair()
    s_pub_key, s_sec_key = crypto_sign_keypair()
    status_cert = create_certificate(["CA Status Server"],
                                     VALID_LENGTH_SEC,
                                     [CertificateUsage.STATUS_SIGNING],
                                     e_pub_key,
                                     s_pub_key,
                                     issuer_hash,
                                     ca_key.signing_private_key)
    with open("status.crt", "wb") as fd:
        fd.write(status_cert.SerializeToString())

    status_key = create_private_key(status_cert, e_sec_key, s_sec_key)
    with open("status.key", "wb") as fd:
        fd.write(status_key.SerializeToString())

    server_hash = CertificateHash()
    server_hash.value = hash_certificate_sha512(server_cert)
    server_hash.algorithm = HashAlgorithm.SHA512
    status_response = CertificateStatusResponse()
    status_response.certificate.CopyFrom(server_hash)
    status_response.status = CertificateStatus.VALID
    status_response.valid_from = int(time.time())
    status_response.valid_length = 60 * 60
    status_response.status_certificate.CopyFrom(status_cert)
    state = crypto_sign_ed25519ph_state()
    state = status_signing_state(state, status_response)
    status_response.status_signature = crypto_sign_ed25519ph_final_create(state, status_key.signing_private_key)
    with open("server_status", "wb") as fd:
        fd.write(status_response.SerializeToString())

async def getStatusCertificate(cert) -> CertificateStatusResponse:
    # Get the certificate from OCSP
    logging.debug("Getting status certificate starting")

    req = CertificateStatusRequest()
    reqCertHash = CertificateHash()
    reqCertHash.value = hash_certificate_sha512(cert)
    reqCertHash.algorithm = HashAlgorithm.SHA512
    req.certificate.CopyFrom(reqCertHash)
    req_data = req.SerializeToString()
    udpClientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udpClientSocket.sendto(req_data, (Settings.StatusServerAddress))
    data, addr = udpClientSocket.recvfrom(1024)
    #resp_size = struct.unpack(">H", data[:2])[0]
    resp = CertificateStatusResponse()
    resp.ParseFromString(data)
    logging.debug("Got status certificate")
    udpClientSocket.close() #Recheck before submitting
    return resp

def validate_certificate(cert, signing_public_key, isServerCert=False, isStatusCert=False) -> bool:
    # What other checks should be performed on a certificate?
    print((len(cert.subjects) == 1 and not isServerCert))
    print((len(cert.subjects) >= 1 and isServerCert))
    print((len(cert.subjects) == 1 and not isServerCert) or (len(cert.subjects) >= 1 and isServerCert))
    if ((len(cert.subjects) == 1 and not isServerCert) or (len(cert.subjects) >= 1 and isServerCert)):
        if isServerCert:
            for s in cert.subjects:
                if not(re.match(Settings.Regexes['dns'], s) or re.match(Settings.Regexes['ipv4'], s) or re.match(Settings.Regexes['ipv6'], s)):
                    logging.debug('Invalid subject: %s', s)
                    return False
        logging.debug("Subject Valid")
        if(cert.valid_from <= int(time.time()) and (cert.valid_from + cert.valid_length) >= int(time.time())):
            logging.debug("Certificate is not expired")
            if((not isStatusCert and len(cert.usages)==1 and cert.usages[0] == CertificateUsage.CLIENT_AUTHENTICATION) or (isStatusCert and len(cert.usages)==1 and cert.usages[0] == CertificateUsage.STATUS_SIGNING)):
                logging.debug("Certificate Usage is valid")
                state = crypto_sign_ed25519ph_state()
                state = certificate_signing_state(state, cert, False)
                if (crypto_sign_ed25519ph_final_verify(state, cert.issuer_signature, signing_public_key)):
                    logging.debug("Certificate signature is valid")
                    return True
            elif (isServerCert and len(cert.usages)==1 and cert.usages[0] == CertificateUsage.SERVER_AUTHENTICATION):
                logging.debug("Certificate Usage is valid")
                state = crypto_sign_ed25519ph_state()
                state = certificate_signing_state(state, cert, False)
                if (crypto_sign_ed25519ph_final_verify(state, cert.issuer_signature, signing_public_key)):
                    logging.debug("Certificate signature is valid")
                    return True
    return False

async def storeRequest(public: bool) -> DecryptedMessage:
    req = StoreRequest()
    req.key = "nayatrykrtehai"
    req.value = b"testreq"
    # req.value = req.value + (b"\x00" * (300 - len(req.value)))
    req.public = public

    rsp = DecryptedMessage()
    rsp.store_request.CopyFrom(req)
    return rsp

async def storeResponse(msg, req):
    h = hashlib.sha512()
    h.update(req.SerializeToString())
    hash = h.digest()
    if msg.hash_algorithm == HashAlgorithm.SHA512 and msg.hash == hash:
        return True
    return False

async def loadRequest():
    req = LoadRequest()
    req.key = ""
    req.public = True
    rsp = DecryptedMessage()
    rsp.load_request.CopyFrom(req)
    return rsp

async def loadResponse(req: LoadResponse) -> DecryptedMessage:
    logging.info("Load Response")
    logging.debug(req.value)

async def pingRequest(req: PingRequest) -> DecryptedMessage:
    rsp = DecryptedMessage()    
    if req.hash_algorithm == HashAlgorithm.SHA512:
        h = hashlib.sha512()
    elif req.hash_algorithm == HashAlgorithm.SHA256:
        h = hashlib.sha256()
    else:
        m = ErrorMessage()
        m.error_message = "Invalid hash algorithm"
        rsp.error_message.CopyFrom(m)
        return rsp

    m = PingResponse()
    h.update(req.data)
    m.hash = h.digest()
    rsp.ping_response.CopyFrom(m)
    return rsp

async def startCommunication(r: asyncio.StreamReader, w: asyncio.StreamWriter, rkey: bytes, wkey: bytes, clientCert: Certificate):
    decryptorBox = SecretBox(rkey)
    encryptorBox = SecretBox(wkey)
    i=0
    while True:
        logging.error(i)
        if i==0:
            req = await storeRequest(public = True)
            logging.debug("Created Store Request")
            logging.info(req)
            reqm = NSTPMessage()
            messageEnc = EncryptedMessage()
            nonce = nonceGenerator(SecretBox.NONCE_SIZE)
            messageEnc.ciphertext = crypto_secretbox(req.SerializeToString(), nonce, wkey)
            messageEnc.nonce = nonce
            reqm.encrypted_message.CopyFrom(messageEnc)
            logging.debug(f"Message Actual Size: {len(reqm.SerializeToString())}")

            logging.debug("Sent Store Request")

            req2 = await loadRequest()
            logging.debug("Created Load Request")
            logging.info(req2)
            reqm2 = NSTPMessage()
            messageEnc = EncryptedMessage()
            nonce = nonceGenerator(SecretBox.NONCE_SIZE)
            messageEnc.ciphertext = crypto_secretbox(req2.SerializeToString(), nonce, wkey)
            messageEnc.nonce = nonce
            reqm2.encrypted_message.CopyFrom(messageEnc)
            
            logging.debug(f"Message Actual Size: {len(reqm.SerializeToString())}")
            
            w.write(struct.pack(">H", len(reqm.SerializeToString())+(len(reqm2.SerializeToString())//2)))
            w.write(reqm.SerializeToString())
            await w.drain()
            await asyncio.sleep(2)
            w.write(reqm2.SerializeToString())
            await w.drain()

            logging.debug("Sent Load Request")
        elif i==1:
            req2 = await loadRequest()
            logging.debug("Created Load Request")
            logging.info(req2)
            reqm = NSTPMessage()
            messageEnc = EncryptedMessage()
            nonce = nonceGenerator(SecretBox.NONCE_SIZE)
            messageEnc.ciphertext = crypto_secretbox(req2.SerializeToString(), nonce, wkey)
            messageEnc.nonce = nonce
            reqm.encrypted_message.CopyFrom(messageEnc)
            #logging.debug(f"Message Actual Size: {len(reqm.SerializeToString())}")
            w.write(struct.pack(">H", len(reqm.SerializeToString())))
            w.write(reqm.SerializeToString())
            await w.drain()

            logging.debug("Sent Load Request")
        else:
            break


        m = NSTPMessage()
        m_size = struct.unpack(">H", await r.readexactly(2))[0]
        k = await r.readexactly(m_size)
        m.ParseFromString(k)
        if not m.HasField("encrypted_message"):
            raise Exception("expected encrypted message")
        msg = DecryptedMessage()
        msg.ParseFromString(crypto_secretbox_open(m.encrypted_message.ciphertext, m.encrypted_message.nonce, rkey))

        if msg.HasField('store_response'):
            logging.info("Got Store Response")
            logging.debug(await storeResponse(msg.store_response, req))
        elif msg.HasField('load_response'):
            logging.info("Got Load Response")
            await loadResponse(msg.load_response)

        elif msg.HasField('ping_request'):
            rsp = await pingRequest(msg.ping_request, clientCert.subjects[0])
        if msg.HasField('error_message'):
            raise Exception("Invalid Data Exchange Message Received")

        if req.HasField('error_message'):
            raise Exception("Invalid Data Exchange Message Received")
        
        i=i+1

async def on_client(r: asyncio.StreamReader, w: asyncio.StreamWriter):
    try:
        m = NSTPMessage()
        m.client_hello.major_version = 4
        m.client_hello.minor_version = 4
        m.client_hello.user_agent = "hi"
        m.client_hello.certificate.CopyFrom(Settings.ServerCert)
        serverStatusCert = Settings.getStatusServerResponse()
        if not serverStatusCert or (serverStatusCert.valid_from + serverStatusCert.valid_length) < int(time.time()):
            serverStatusCert = await getStatusCertificate(m.client_hello.certificate)
            Settings.setStatusServerResponse(serverStatusCert)
        m.client_hello.certificate_status.CopyFrom(serverStatusCert)
        m_data = m.SerializeToString()
        w.write(struct.pack(">H", len(m_data)))
        w.write(m_data)
        await w.drain()

        logging.info("Client Hello Sent")

        hello = NSTPMessage()
        hello_size = struct.unpack(">H", await r.readexactly(2))[0]
        hello.ParseFromString(await r.readexactly(hello_size))
        
        if not hello.HasField("server_hello"):
            raise Exception("expected server hello")
        if hello.server_hello.major_version != 4:
            raise Exception("unexpected server version")
        
        logging.info("Server hello: Received")

        # Create our own hello


        #Check if certificate is pinned
        isPinned = False
        if hello.server_hello.HasField("certificate") and len(hello.server_hello.certificate.subjects) == 1:
            pinnedCert = Settings.PinnedCertStore.get(hello.client_hello.certificate.subjects[0])
            if pinnedCert:
                if pinnedCert.algorithm == HashAlgorithm.SHA256:
                    h = hashlib.sha256()
                elif pinnedCert.algorithm == HashAlgorithm.SHA512:
                    h = hashlib.sha512()
                else:
                    raise Exception("unexpected hash algorithm in pinned certiicate")
                
                if hash_certificate(h, hello.server_hello.certificate) == pinnedCert.value:
                    isPinned = True
                else:
                    raise Exception("pinned certificate does not match")

        if not isPinned:

            if hello.server_hello.certificate.issuer.algorithm == HashAlgorithm.SHA256:
                h = hashlib.sha256()
            elif hello.server_hello.certificate.issuer.algorithm == HashAlgorithm.SHA512:
                h = hashlib.sha512()
            else:
                raise Exception("unexpected hash algorithm")

            for ca in Settings.CAStore.certificates:
                if (hash_certificate(h,ca) == hello.server_hello.certificate.issuer.value) and ca.valid_from <= int(time.time()) and (ca.valid_length + ca.valid_from >= int(time.time())):
                    ca_cert = ca
                    break
            
            if not ca_cert:
                #Need to look for self-signed certificate
                raise Exception("no matching CA found")

            # Check the certificate
            if not hello.server_hello.HasField("certificate_status"):
                # Get the certificate from OCSP
                ocspResponse = await getStatusCertificate(hello.server_hello.certificate)
                hello.server_hello.certificate_status.CopyFrom(ocspResponse)

            if hello.server_hello.certificate_status.certificate.algorithm == HashAlgorithm.SHA256:
                h = hashlib.sha256()
            elif hello.server_hello.certificate_status.certificate.algorithm == HashAlgorithm.SHA512:
                h = hashlib.sha512()
            else:
                raise Exception("unexpected hash algorithm")

            logging.info('Status Server Certificate Verification')

            if hash_certificate(h, hello.server_hello.certificate) != hello.server_hello.certificate_status.certificate.value:
                raise Exception("certificate does not match in OCSP response")

            if not (hello.server_hello.certificate_status.status == CertificateStatus.VALID and (hello.server_hello.certificate_status.valid_from + hello.server_hello.certificate_status.valid_length) >= int(time.time()) and hello.server_hello.certificate_status.valid_from <= int(time.time())):
                raise Exception(f"OCSP Certificate Status: {hello.server_hello.certificate_status.status} \nValid From: {hello.server_hello.certificate_status.valid_from} \nValid Length: {hello.server_hello.certificate_status.valid_length} \nCurrent Time: {int(time.time())}")
            
            if not validate_certificate(hello.server_hello.certificate_status.status_certificate, ca_cert.signing_public_key, False, True):
                raise Exception("OCSP certificate validation failed")

            ocspState = crypto_sign_ed25519ph_state()
            ocspState = status_signing_state(ocspState, hello.server_hello.certificate_status)
            if not crypto_sign_ed25519ph_final_verify(ocspState, hello.server_hello.certificate_status.status_signature, hello.server_hello.certificate_status.status_certificate.signing_public_key):
                raise Exception("OCSP Response signature validation failed")

            logging.info('Status Server Certificate Verification')
            logging.debug(hello.server_hello.certificate)
            if not validate_certificate(hello.server_hello.certificate, ca_cert.signing_public_key, True, False):
                raise Exception("certificate validation failed")

            r_key, w_key = crypto_kx_client_session_keys(Settings.ServerCert.encryption_public_key,
                                                    Settings.ServerKey.encryption_private_key,
                                                    hello.server_hello.certificate.encryption_public_key)
            
            await startCommunication(r, w, r_key, w_key, hello.server_hello.certificate)

    except asyncio.exceptions.IncompleteReadError as e:
        logging.error('Connection closed by client')
        w.close()
        await w.wait_closed()

    except Exception as e:
        logging.error(traceback.print_exc())
        w.close()
        await w.wait_closed()

async def nstpdClient(configFile):
    logging.info("Starting NSTP server")
    configs = tomlkit.load(open(configFile, "r"))
    
    Settings.CAStore.ParseFromString(open(configs["trusted_certificate_store"], "rb").read())
    logging.info("Loaded trusted CA store")
    logging.debug(Settings.CAStore)
    
    Settings.ServerCert.ParseFromString(open(configs["client_certificate"], "rb").read())
    logging.info("Loaded client certificate")
    logging.debug(Settings.ServerCert)

    Settings.ServerKey.ParseFromString(open(configs["client_private_key"], "rb").read())
    logging.info("Loaded client private key")
    logging.debug(Settings.ServerKey)

    Settings.PinnedCertStore.ParseFromString(open(configs["pinned_certificate_store"], "rb").read())
    Settings.PinnedCertStore = { x.subject: x.certificate for x in Settings.PinnedCertStore.pinned_certificates}
    logging.info("Loaded pinned certificate store")
    logging.debug(Settings.PinnedCertStore)

    Settings.setServerAddress(configs["nstp_server_address"])
    Settings.setStatusServerAddress(configs["status_server_address"])
    logging.info("Loaded NSTP server address")
    logging.debug(Settings.ServerAddress)
    logging.info("Loaded status server address")
    logging.debug(Settings.StatusServerAddress)

    # Settings.openDataStore()

    try:
        r,w = await asyncio.open_connection(Settings.ServerAddress[0], Settings.ServerAddress[1])
        await on_client(r,w)
    except Exception as e:
        logging.error(traceback.print_exc())
        w.close()
        await w.wait_closed()
# atexit.register(Settings.closeDataStore)
def main():
    # init_pki()
    asyncio.run(nstpdClient("projectConfig.toml")) #sys.argv[1]


if __name__ == "__main__":
    main()

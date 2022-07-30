# Network Security Transport Protocol

This project was a part of a submission to the cybersecurity course CY6740 Network Security. The goal of the project was to understand trust relationships between PKI participants, learn to detect and mitigate attacks against PKI. The assignment required students to implement TLS-style secure transport layer for TCP connections. 

Here we are trying to replicate the Network Security Transport Protocol (NSTP) that uses a Public Key Infrastructure (PKI) to authenticate participants allowing access to a centralized key-value store. Each participant uses a local certificate authority database and online certificate status servers to verify the identity of peers.

### Protocol Phases
NSTP operates majorly in two phases:

1. **Initialization Phase** where clients and servers exchange messages mentioning versioning information and negotiate on session keys and their parameters.
2. **Data Exchange Phase** where authenticated clients can make multiple application level requests over the encrypted channel.

## Initialization Phase

During the initialization phase, clients and servers exchange `ClientHello` and `ServerHello` messages as shown below. 

```proto
message ClientHello {
  uint32 major_version = 1;   // Must be 4
  uint32 minor_version = 2;
  string user_agent = 3;
  Certificate certificate = 4;
  CertificateStatusResponse certificate_status = 5;
}

message ServerHello {
  uint32 major_version = 1;
  uint32 minor_version = 2;
  string user_agent = 3;
  Certificate certificate = 4;
  CertificateStatusResponse certificate_status = 5;
}
```
*Note: `libsodium` was used to perform key negotiations and to symmetrically encrypt messages*

### Certificates

NSTP certificates are conceptually a subset of X.509 certificates. Certificate validation is done using following rules for each certificate in a validation chain:
  - Certificate subjects must match:
    - Client certificates contains a single subject that is interpreted as a username.
    - Server certificates may carry multiple subjects where a subject must be either a valid DNS name or IPv{4,6} address for the server.
  - Certificate issuers must refer to a trusted certificate, or be self-signed if it belongs to a trust root
  - Certificates must be valid at the time of verification
  - Certificates must be labeled with an appropriate usage flag
  - Certificate signatures must pass verification against the corresponding public key
  - Certificates must be labeled as valid by a status server

```proto
message CertificateStore {
    repeated Certificate certificates = 1;
}

message Certificate {
    repeated string subjects = 1;
    uint64 valid_from = 2;
    uint32 valid_length = 3;
    repeated CertificateUsage usages = 4;
    bytes encryption_public_key = 5;
    bytes signing_public_key = 6;
    CertificateHash issuer = 7;
    bytes issuer_signature = 8;
}

enum CertificateUsage {
    CERTIFICATE_SIGNING = 0;
    CLIENT_AUTHENTICATION = 1;
    SERVER_AUTHENTICATION = 2;
    STATUS_SIGNING = 3;
}

message CertificateHash {
    bytes value = 1;
    HashAlgorithm algorithm = 2;
}

message PrivateKey {
    CertificateHash certificate = 1;
    bytes encryption_private_key = 2;
    bytes signing_private_key = 3;
}
```
*Note: Signatures were computed over each field of a certificate in the order they appear in the Certificate protobuf message, except for the trailing signature field itself. The signature algorithm used here is `Ed25519`*

### Certificate Status Server

Status servers are UDP servers that are responsible for indicating whether certificates are valid, have been revoked, or are unknown to the server. A valid status is required for a certificate to pass validation. The application checks for stapled certificate status response to a certificate from sender otherwise, receiver query a status server for certificate status response.

Regardless of whether a certificate status response has been stapled or obtained directly, it is validated similarly to a certificate with an additional validation constraint that the certificate and status server certificate must share a common trust root.

```proto
message CertificateStatusRequest {
    CertificateHash certificate = 1;
}

message CertificateStatusResponse {
    CertificateHash certificate = 1;
    CertificateStatus status = 2;
    uint64 valid_from = 3;
    uint32 valid_length = 4;
    Certificate status_certificate = 5;
    bytes status_signature = 6;
}

enum CertificateStatus {
    UNKNOWN = 0;
    VALID = 1;
    REVOKED = 2;
}
```
*Note: Certificate status requests and responses use certificate hashes to uniquely identify a certificate which are computed over each field of a certificate in the order they appear in the Certificate protobuf message using either SHA-256 or SHA-512.*

### Certificate Pinning
As a supplement to certificate path validation, certificates may be “pinned.” If a presented certificate does not match a pinned certificate, then it is rejected regardless of whether it passes validation or not.

```proto
message PinnedCertificateStore {
    repeated PinnedCertificate pinned_certificates = 1;
}

message PinnedCertificate {
    string subject = 1;
    CertificateHash certificate = 2;
}
```
## Data Exchange Phase
Multiple application level requests can be made over the established secure channel. All messages are encrypted using the libsodium authenticated encryption API and previously-established session key. An `EncryptedMessage` protobufs are sent over the channel which expected to decrypt to `DecryptedMessage` protobufs.

There are three operations supported by the application protocol:
  - **Ping** : A hash is calculated and sent as response for the data sent through request using the requested hashing algorithm.
  - **Load** : Load data stored at the requested key in the public or private key-value store as per the request.
  - **Store** : Store data at the requested key in the public or private key-value store as per the request.

*Note: 
- If a value is private, then that value exists in a user-specific namespace so that it is only readable or writable by the owning user. If a value is public, then that value exists in a public namespace where any user can access and modify the value.
- The store created is persistent.
- The store is created using filesystem where there is public directory and user-specific directories containing files with the name of keys and value as the files content.
*

```proto
message EncryptedMessage {
    bytes ciphertext = 1;
    bytes nonce = 2;
}

message DecryptedMessage {
    oneof message_ {
        ErrorMessage error_message = 1;
        PingRequest ping_request = 2;
        PingResponse ping_response = 3;
        LoadRequest load_request = 4;
        LoadResponse load_response = 5;
        StoreRequest store_request = 6;
        StoreResponse store_response = 7;
    }
}

message ErrorMessage {
    string error_message = 1;
}

message PingRequest {
    bytes data = 1;
    HashAlgorithm hash_algorithm = 2;
}

message PingResponse {
    bytes hash = 1;
}

message LoadRequest {
    string key = 1;
    bool public = 2;
}

message LoadResponse {
    bytes value = 1;
}

message StoreRequest {
    string key = 1;
    bytes value = 2;
    bool public = 3;
}

message StoreResponse {
    bytes hash = 1;
    HashAlgorithm hash_algorithm = 2;
}
```

## Configuration
To run the server application a toml needs to be created accordingly
```toml
nstp_server_address = "0.0.0.0:1500"    # NSTP server configuration
status_server_address = "10.1.2.3:1501"   # Status server configuration
trusted_certificate_store = "/data/trusted_certs.db"    # Path to a CA store
pinned_certificate_store = "/data/pinned_certs.db"    # Path to a pinned certificate store
server_certificate = "/data/server.crt"   # Path to the server certificate
server_private_key = "/data/server.key"   # Path to the server private key
```

## Build and Run

To generate PKIs, uncomment `init_pki()` in `main()` in `main.py` and comment `asyncio.run(nstpd(sys.argv[1]))` and run the script.

To build and run this project, you need [docker installed](https://docs.docker.com/engine/install/) on your machine.

Once docker is installed, clone the repository, and follow these steps:

1. Build the docker image - `docker build --pull --rm -f "nstpd/Dockerfile" -t <image_name>:latest "nstpd"`
2. To generate PKIs, uncomment `init_pki()` in `main()` in `main.py` and comment `asyncio.run(nstpd(sys.argv[1]))` and run the script `python3 ./main.py`.
3. Run the Status Server - `python3 status_server.py`
4. Run the Server docker image - `docker run -it --rm --network="host" -v <host_path>/data:/data:ro <image_name> /data/config.toml`
5. Run the Client `client.py`
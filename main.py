#! /usr/bin/env nix-shell
#! nix-shell -i python3 -p python3Packages.requests -p python3Packages.pyjwt -p openssl -p pkg-config -p python3Packages.noiseprotocol
#! nix-shell -i python3 -p python3Packages.requests -p python3Packages.pyjwt -p python3Packages.noiseprotocol


import argparse
import json
import requests
import secrets

from typing import Optional, Mapping, List, Final

import jwt

from noise.connection import NoiseConnection, Keypair
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import serialization


# NOTE, in practice, the communication to OIDC and salt must be over TLS
OIDC_PROVIDER_URL = "http://127.0.0.1:5000/"
# NOTE this is the stratus client
OIDC_PROVIDER_URL = "http://bias.fi.muni.cz/oidc"
# SALT_SERVICE_URL = "http://127.0.0.1:5001/"
SALT_SERVICE_URL = "http://bias.fi.muni.cz/salt-service"

zkLogin_client_name: Final[str] = "zkLogin"
zkLogin_audience: Final[str] = "zkLogin"
zkLogin_client_metadata = {
    "client_name": zkLogin_client_name,
    "client_uri": "zkLogin_uri",
    "grant_type": "authorization_code",
    "redirect_uri": "https://example.com/",
    "aud": zkLogin_audience,
    "response_type": "code",
    "scope": "openid profile",
    "token_endpoint_auth_method": "client_secret_basic",
}


def login_user_to_oidc_provider(username: str) -> Optional[str]:
    """
    Logs in `username` with the OIDC provider and returns the user's
    ID that should be used as the reference for later requests.

    The registration of `username` is implicit on the first login.
    """
    # NOTE there no passwords for authentication
    resp = requests.post(
        OIDC_PROVIDER_URL, data={"username": username}, allow_redirects=False
    )
    session_id = resp.cookies.get("session")
    return session_id


def register_oidc_client_service(
    username: str, client_metadata: Mapping[str, str]
) -> List:
    session_id = login_user_to_oidc_provider(username)
    resp = requests.post(
        f"{OIDC_PROVIDER_URL}/create_client",
        cookies={"session": session_id},
        data=client_metadata,
        allow_redirects=True,
    )
    return resp.status_code


def get_oidc_registered_clients(username: str) -> List:
    session_id = login_user_to_oidc_provider(username)
    resp = requests.get(
        f"{OIDC_PROVIDER_URL}/", cookies={"session": session_id}, allow_redirects=True
    )
    return resp.json()


def authorize_zkLogin_client(username: str, nonce: str = secrets.token_hex(32)) -> str:
    session_id = login_user_to_oidc_provider(username)
    params = {
        "client_id": get_zkLogin_client(username)["info"]["client_id"],
        "scope": "openid profile",
        "response_type": "code",
        "nonce": nonce,
    }
    # the following GET is not required, we could go straight to the POST
    requests.get(
        f"{OIDC_PROVIDER_URL}/oauth/authorize/",
        params=params,
        cookies={"session": session_id},
        allow_redirects=True,
    )
    # NOTE always authorize/confirm the use
    resp = requests.post(
        f"{OIDC_PROVIDER_URL}/oauth/authorize",
        params=params,
        data={"confirm": True},
        cookies={"session": session_id},
        allow_redirects=True,
    )
    # NOTE recovering the authorization code form the url is messy, but works for now
    return resp.url.split("?")[-1].split("=")[-1]


def get_jwt(username: str):
    # session_id = login_user_to_oidc_provider(username)
    zkLogin_client = get_zkLogin_client(username)
    client_id = zkLogin_client["info"]["client_id"]
    client_secret = zkLogin_client["info"]["client_secret"]
    basic_auth = requests.auth.HTTPBasicAuth(client_id, client_secret)

    # NOTE authorizing the client each time seems wasteful, but we need get the `code` somehow
    code = authorize_zkLogin_client(username)
    data = {"grant_type": "authorization_code", "code": code}

    resp = requests.post(f"{OIDC_PROVIDER_URL}/oauth/token", auth=basic_auth, data=data)
    return resp.json()


def get_zkLogin_client(username: str) -> Mapping:
    """
    Gets the zkLogin client. If it does not exitst at first, it creates it.
    """
    clients = get_oidc_registered_clients(username)
    for client in clients:
        if client["metadata"]["client_name"] == zkLogin_client_name:
            return client

    # creat the client and now return as it is expected to have been created
    register_oidc_client_service(username, zkLogin_client_metadata)
    clients = get_oidc_registered_clients(username)
    for client in clients:
        if client["metadata"]["client_name"] == zkLogin_client_name:
            return client


def get_oidc_public_key():
    resp = requests.get(f"{SALT_SERVICE_URL}/get-single-card-public")
    return resp.json()["single-card-public-key"]


def get_salt(token) -> bytes:
    resp = requests.post(f"{SALT_SERVICE_URL}/get-salt", data={"jwt": token})
    return resp.json()


def get_encrypted_salt(token) -> bytes:
    eph_privkey = ed25519.Ed25519PrivateKey.generate()
    eph_pubkey = eph_privkey.public_key()
    eph_pubkey_bytes = eph_pubkey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    card_pubkey = load_pem_public_key(get_oidc_public_key().encode())

    proto = NoiseConnection.from_name(b"Noise_NK_25519_ChaChaPoly_SHA256")
    # proto.set_keypair_from_private_bytes(
    #     Keypair.EPHEMERAL,
    #     eph_privkey.private_bytes(
    #         encoding=serialization.Encoding.Raw,
    #         format=serialization.PrivateFormat.Raw,
    #         encryption_algorithm=serialization.NoEncryption(),
    #     ),
    # # )
    proto.set_keypair_from_public_bytes(
        Keypair.REMOTE_STATIC,
        card_pubkey.public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        ),
    )
    proto.set_as_initiator()
    proto.start_handshake()

    ciphertext = proto.write_message(token)
    # print("eph", eph_pubkey_bytes.hex())
    # print("ct", ct.hex())

    resp = requests.post(
        f"{SALT_SERVICE_URL}/get-salt-e2e", data={"payload": ciphertext.hex()}
    )
    enc_salt = resp.json()["enc-salt"]
    # print(f"Encrypted salt: {enc_salt}")
    salt = proto.read_message(bytes.fromhex(enc_salt))
    return {"salt": salt.hex()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--username", default="jan")
    args = parser.parse_args()
    username = args.username

    payload = get_jwt(username)
    token = payload["id_token"].encode()

    oidc_pub = b"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKp9RBOl7QILm9KSbgSaCQbj1OSFL\nFE7Euvk3hnDlTqpM4fxPT0h/E5sh3+DQiUo49dT72OIM/KVdXmIqw1J50g==\n-----END PUBLIC KEY-----\n"

    decoded = jwt.decode(
        token, oidc_pub, audience=[zkLogin_audience], algorithms=["ES256"]
    )

    out = {
        "JWT": token.decode(),
        "JWT decoded": decoded,
        "salt": get_salt(token),
        "salt via e2ee channel": get_encrypted_salt(token),
    }
    print(json.dumps(out, indent=4))


if __name__ == "__main__":
    main()

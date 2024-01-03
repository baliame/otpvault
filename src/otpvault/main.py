"""
Module for the encrypted key store object.
"""
import argparse
import getpass
import hashlib
import os
import sys
from pathlib import Path

import yaml
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.padding import PKCS7
import pyotp


class OTPStore:
    """
    Encrypted key storage for OTP credentials.

    Attributes
    ----------
    keylist_file : pathlib.Path
        Encrypted binary which stores the OTP credentials.
    nonce_file : pathlib.Path
        Nonce file for the encryption.
    nonce : bytes
        The nonce value.
    keylist_cipher : cryptography.hazmat.primitives.cipher.Cipher
        The cryptography cipher used to decrypt and encrypt the key storage.
    keys : dict
        A list of decrypted key pairs, keyed by account name.
    """

    def __init__(self, config_path):
        """
        Initializes a Keystore object.

        Parameters
        ----------
        config : awsc.config.config.Configuration
            The parent configuration object instance.
        """
        config_path.mkdir(mode=0o755, parents=True, exist_ok=True)
        self.keylist_file = config_path / "secrets"
        self.nonce_file = config_path / "nonce"
        self.keylist_cipher = None
        self.nonce = os.urandom(16)
        self.keys = {}

    def do_unlock(self, password):
        """
        Unlock keystore with a password.
        """
        sha = hashlib.sha256(password.encode("ascii"))
        if not self.nonce_file.exists():
            with self.nonce_file.open("wb") as file:
                file.write(self.nonce)
        else:
            with self.nonce_file.open("rb") as file:
                self.nonce = file.read()
        self.keylist_cipher = Cipher(AES(sha.digest()), CBC(self.nonce))

        if self.keylist_file.exists():
            self.parse_keylist()

    def unlock(self):
        """
        Prompts the user to enter the password to access the key storage, and parses the keylist file.
        """
        password = getpass.getpass(
            "Enter encryption phrase for key database: ",
        )
        self.do_unlock(password)

    def parse_keylist(self):
        """
        Attempts to parse the keylist file.

        Should be called through unlock(), as unlock() generates the cipher for this method.
        """
        try:
            with self.keylist_file.open("rb") as file:
                data = file.read()
            dec = self.keylist_cipher.decryptor()
            yaml_decoded = dec.update(data) + dec.finalize()
            unpadder = PKCS7(256).unpadder()
            yaml_decoded = unpadder.update(yaml_decoded) + unpadder.finalize()
            self.keys = yaml.safe_load(yaml_decoded.decode("UTF-8"))
            changed = False
            for key in self.keys:
                if "temp" in self.keys[key]:
                    changed = True
                    self.keys[key].pop("temp")
            if changed:
                self.write_keylist()
        except ValueError:
            print("Incorrect password.")
            sys.exit(1)

    def write_keylist(self):
        """
        Writes the keylist to the keylist_file. Cipher must be loaded through unlock() before writing.
        """
        enc = self.keylist_cipher.encryptor()
        yaml_encoded = yaml.dump(self.keys).encode("UTF-8")
        padder = PKCS7(256).padder()
        padded = padder.update(yaml_encoded) + padder.finalize()
        data = enc.update(padded) + enc.finalize()
        with self.keylist_file.open("wb") as file:
            file.write(data)

    def __getitem__(self, item):
        """
        Returns the named OTP secret.

        Parameters
        ----------
        item : str
            Name of the keypair to fetch.

        Returns
        -------
        dict
            A dict containing the access and secret keys.
        """
        return self.keys[item]

    def __contains__(self, item):
        return item in self.keys

    def __iter__(self):
        return iter(self.keys)

    def set_key(self, name, secret):
        """
        Upserts a key into the key storage and writes to disk.

        Parameters
        ----------
        name : str
            The name of the keypair.
        secret : str
            The OTP secret key.
        """
        self.keys[name] = {"otp_secret": secret}
        self.write_keylist()

    def delete_key(self, name):
        """
        Deletes a key from the key storage and writes to disk.

        Parameters
        ----------
        name : str
            The name of the key to delete.
        """
        del self.keys[name]
        self.write_keylist()


def main():
    parser = argparse.ArgumentParser(
        prog="OTP Vault",
        description="Generates OTP credentials",
    )
    parser.add_argument("command", choices=["add", "list", "get", "generate", "remove"])
    parser.add_argument("-n", "--name", default="")
    args = parser.parse_args()
    if args.command in ["add", "get", "generate", "remove"] and args.name == "":
        print(
            f"Name (-n / --name) is required for command {args.command}",
            file=sys.stderr,
        )
        sys.exit(1)
    storage = OTPStore(Path.home() / ".config" / "otpstore")
    storage.unlock()
    if args.command == "add":
        otp_secret = getpass.getpass(
            f"Enter secret key for otp pass {args.name}: ",
        )
        storage.set_key(args.name, otp_secret)
        print(f"Added or updated OTP key {args.name}")
    elif args.command == "remove":
        if args.name not in storage:
            print(f"OTP key {args.name} does not exist.")
            sys.exit(1)
        storage.delete_key(args.name)
        print(f"Removed OTP key {args.name}")
    elif args.command == "list":
        for key in storage:
            print(key)
    elif args.command == "generate":
        if args.name not in storage:
            print(f"OTP key {args.name} does not exist.")
            sys.exit(1)
        totp = pyotp.TOTP(storage[args.name]["otp_secret"])
        print(totp.now())
    elif args.command == "get":
        if args.name not in storage:
            print(f"OTP key {args.name} does not exist.")
            sys.exit(1)
        print(storage[args.name]["otp_secret"])

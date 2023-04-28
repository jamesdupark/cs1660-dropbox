##
## client.py - Dropbox client implementation
##

# ** Optional libraries, uncomment if you need them **
# Search "python <name> library" for documentation
#import string  # Python library with useful string constants
#import dacite  # Helpers for serializing dicts into dataclasses
#import pymerkle # Merkle tree implementation (CS1620/CS2660 only, but still optional)

## ** Support code libraries ****
# The following imports load our support code from the "support"
# directory.  See the Dropbox wiki for usage and documentation.
import support.crypto as crypto                   # Our crypto library
import support.util as util                       # Various helper functions

# These imports load instances of the dataserver, keyserver, and memloc classes
# to use in your client. See the Dropbox Wiki and setup guide for examples.
from support.dataserver import dataserver, memloc
from support.keyserver import keyserver

# **NOTE**:  If you want to use any additional libraries, please ask on Ed
# first.  You are NOT permitted to use any additional cryptographic functions
# other than those provided by crypto.py, or any filesystem/networking libraries.

class User:
    def __init__(self) -> None:
        """
        Class constructor for the `User` class.

        You are free to add fields to the User class by changing the definition
        of this function.
        """

    def upload_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/upload-file.html
        """
        # TODO: Implement
        raise util.DropboxError("Not Implemented")

    def download_file(self, filename: str) -> bytes:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/download-file.html
        """
        # TODO: Implement
        raise util.DropboxError("Not Implemented")

    def append_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/append-file.html
        """
        # TODO: Implement
        raise util.DropboxError("Not Implemented")

    def share_file(self, filename: str, recipient: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/share-file.html
        """
        # TODO: Implement
        raise util.DropboxError("Not Implemented")

    def receive_file(self, filename: str, sender: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/receive-file.html
        """
        # TODO: Implement
        raise util.DropboxError("Not Implemented")

    def revoke_file(self, filename: str, old_recipient: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/revoke-file.html
        """
        # TODO: Implement
        raise util.DropboxError("Not Implemented")
    

def encrypt(base_key: bytes, purpose: str, data: bytes):
    """
    Derives a new key from the base_key to encrypt the given data, then signs it using a given
    sign_key.
    """
    enc_key = crypto.HashKDF(base_key, purpose)
    enc_data = crypto.SymmetricEncrypt(enc_key, crypto.SecureRandom(16), data)
    return enc_data

def create_memloc(base_key: bytes, purpose: str) -> bytes:
    return crypto.HashKDF(base_key, purpose+"_memloc")


def create_user(username: str, password: str) -> User:
    """
    The specification for this function is at:
    http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/authentication/create-user.html
    """
    # Initialize a User object
    current_user = User()
    
    # Initialize necessary keys
    base_key = crypto.PasswordKDF(username+password, 
                                  crypto.HashKDF(util.ObjectToBytes(username+password), "base_key_salt"), 
                                  16)
    pub_key, priv_key = crypto.AsymmetricKeyGen()
    verify_key, sign_key = crypto.SignatureKeyGen()

    # Check if username is already taken, or is empty string
    if username == "":
        raise util.DropboxError("Usernames cannot be empty.")
    
    try:
        keyserver.Get(username+"pub_key")
    except ValueError:
        pass
    else:
        raise util.DropboxError("Username already exists; please choose a new username.")

    # Store public keys in the Keyserver
    keyserver.Set(username+"pub_key", 
                  pub_key)
    keyserver.Set(username+"verify_key", 
                  verify_key)

    # Store private keys in the Dataserver
    dataserver.Set(create_memloc(base_key, username+"priv_key_storage"),
                   encrypt(base_key, "priv_key_storage", bytes(priv_key))
                   )
    dataserver.Set(create_memloc(base_key, username+"sign_key_storage"),
                   encrypt(base_key, "sign_key_storage", bytes(sign_key))
                   )

def authenticate_user(username: str, password: str) -> User:
    """
    The specification for this function is at:
    http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/authentication/authenticate-user.html
    """
    # Initialize a User object and the base key
    current_user = User()
    base_key = crypto.PasswordKDF(username+password, 
                                  crypto.HashKDF(util.ObjectToBytes(username+password), "base_key_salt"), 
                                  16)
    # Locate and retrieve public keys
    pub_key = keyserver.Get(username+"pub_key")
    verify_key = keyserver.Get(username+"verify_key")
    
    # Locate and retrieve private/sign key
    try:
        priv_key_get = dataserver.Get(create_memloc(base_key, username+"priv_key_storage"))
    except:
        raise util.DropboxError("Authentication Error- Check Your Username/Password!")
    priv_key = crypto.SymmetricDecrypt(crypto.HashKDF(base_key, "priv_key_storage"),
                                       priv_key_get)
    
    try:
        sign_key_get = dataserver.Get(create_memloc(base_key, username+"sign_key_storage"))
    except:
        raise util.DropboxError("Authentication Error- Check Your Username/Password!")
    sign_key = crypto.SymmetricDecrypt(crypto.HashKDF(base_key, "sign_key_storage"),
                                       sign_key_get)

    # Confirm encryption/decryption keys
    auth_msg = b"The Treaty of Versailles[4] was a peace treaty signed on 28 June 1919."
    enc_msg = crypto.AsymmetricEncrypt(pub_key, auth_msg)
    dec_msg = crypto.AsymmetricDecrypt(crypto.AsymmetricDecryptKey.from_bytes(priv_key), enc_msg)

    if dec_msg != auth_msg:
        raise util.DropboxError("Authentication Error- Check Your Username/Password!")
    
    # Confirm signature/verify keys
    sign_msg = crypto.SignatureSign(crypto.SignatureSignKey.from_bytes(sign_key),
                                    enc_msg)
    verify_msg = crypto.SignatureVerify(verify_key, enc_msg, sign_msg)
    if verify_msg != True:
        raise util.DropboxError("Authentication Error - Check Your Username/Password!")
    
    # If both pass, return the User object
    return current_user


create_user("bob", "pw")
authenticate_user("bob", "sw")
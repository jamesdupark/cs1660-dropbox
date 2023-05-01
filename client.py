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
    def __init__(self, *args) -> None:
        """
        Class constructor for the `User` class.

        Initializes a base key for key generation and optionally sets public and private
        encryption/signature key fields if given.

        Parameters:
            - un: str - username of the User
            - pw: str - password of the User
        Optional Parameters:
            - pub_key: crypto.AsymmetricEncryptKey - public encryption key of the User
            - priv_key: crypto.AsymmetricDecryptKey - private decryption key of the User
            - verify_key: crypto.SignatureVerifyKey - public verification key of the User
            - sign_key: crypto.SignatureSignKey - private signature key of the User
        Fields:
            - un: str - username of the User
            - base_key - base key of the User, used to generate other symmetric keys and memlocs
            - pub_key: crypto.AsymmetricEncryptKey - public encryption key of the User
            - priv_key: crypto.AsymmetricDecryptKey - private decryption key of the User
            - verify_key: crypto.SignatureVerifyKey - public verification key of the User
            - sign_key: crypto.SignatureSignKey - private signature key of the User
        """
        if len(args) == 2:
            self.un, pw = args[0], args[1]
        if len(args) == 6:
            self.un, pw, self.pub_key, self.priv_key, self.verify_key, self.sign_key = \
            args[0], args[1], args[2], args[3], args[4], args[5]

        else:
            raise TypeError("Incorrect number of arguments for User")

        self.base_key = crypto.PasswordKDF(self.un+pw, 
                                  crypto.HashKDF(util.ObjectToBytes(self.un+pw), "base_key_salt"), 
                                  16)
        
    def authenticate(self, username: str, password: str) -> None:
        """
        Retrieves/verifies public/private keys from the Keyserver and Dataserver.

        Paramters:
            - username: username of the User
            - password: password of the User
        Raises:
            - util.DropboxError: if username/password authentication fails
        """
        # Locate and retrieve public keys
        try:
            pub_key = keyserver.Get(username+"pub_key")
            verify_key = keyserver.Get(username+"verify_key")
        except ValueError:
            raise util.DropboxError("Authentication Error- No such User exists.")
        
        # Locate and retrieve private/sign key
        try:
            priv_key_get = dataserver.Get(create_memloc(self.base_key, username+"priv_key_storage"))
        except:
            raise util.DropboxError("Authentication Error- Check Your Username/Password!")
        priv_key = crypto.SymmetricDecrypt(crypto.HashKDF(self.base_key, "priv_key_storage"),
                                        priv_key_get)
        
        try:
            sign_key_get = dataserver.Get(create_memloc(self.base_key, username+"sign_key_storage"))
        except:
            raise util.DropboxError("Authentication Error- Check Your Username/Password!")
        sign_key = crypto.SymmetricDecrypt(crypto.HashKDF(self.base_key, "sign_key_storage"),
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
        
        # keys have been verified, assign to fields
        self.pub_key = pub_key
        self.priv_key = priv_key
        self.verify_key = verify_key
        self.sign_key = sign_key

    def upload_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/upload-file.html
        """
        # TODO: Implement
        
        # iterate over chunks of the bytes
        for i in range(0, len(data)):
            pass




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
    
def encrypt(base_key: bytes, purpose: str, data: bytes) -> bytes:
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
    # Initialize necessary keys
    pub_key, priv_key = crypto.AsymmetricKeyGen()
    verify_key, sign_key = crypto.SignatureKeyGen()

    # Initialize User object
    current_user = User(username, password, pub_key, priv_key, verify_key, sign_key)

    # Check if username is already taken, or is empty string
    if username == "":
        raise util.DropboxError("Usernames cannot be empty.")
    
    try:
        keyserver.Get(username+"pub_key")
    except ValueError: # if no entry with the same username exists in keyserver, we may continue
        pass
    else:
        raise util.DropboxError("Username already exists; please choose a new username.")

    # Store public keys in the Keyserver
    keyserver.Set(username+"pub_key", 
                  pub_key)
    keyserver.Set(username+"verify_key", 
                  verify_key)

    # Store private keys in the Dataserver
    dataserver.Set(create_memloc(current_user.base_key, username+"priv_key_storage"),
                   encrypt(current_user.base_key, "priv_key_storage", bytes(priv_key))
                   )
    dataserver.Set(create_memloc(current_user.base_key, username+"sign_key_storage"),
                   encrypt(current_user.base_key, "sign_key_storage", bytes(sign_key))
                   )
    
    return current_user

def authenticate_user(username: str, password: str) -> User:
    """
    The specification for this function is at:
    http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/authentication/authenticate-user.html
    """
    # Initialize a User object
    current_user = User(username, password)

    # call authenticate method to fill out keys
    current_user.authenticate(username, password)

    # If both pass, return the User object
    return current_user


create_user("bob", "pw")
authenticate_user("bob", "sw")
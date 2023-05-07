##
# client.py - Dropbox client implementation
##

# ** Optional libraries, uncomment if you need them **
# Search "python <name> library" for documentation
# import string  # Python library with useful string constants
# import dacite  # Helpers for serializing dicts into dataclasses
# import pymerkle # Merkle tree implementation (CS1620/CS2660 only, but still optional)

# ** Support code libraries ****
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
            - shared_files: dictionary - shared filenames as keys, file owner as value
        Fields:
            - un: str - username of the User
            - base_key - base key of the User, used to generate other symmetric keys and memlocs
            - pub_key: crypto.AsymmetricEncryptKey - public encryption key of the User
            - priv_key: crypto.AsymmetricDecryptKey - private decryption key of the User
            - verify_key: crypto.SignatureVerifyKey - public verification key of the User
            - sign_key: crypto.SignatureSignKey - private signature key of the User
            - shared_files: dictionary - shared filenames as keys, file owner as value
        """
        if len(args) == 2:
            self.un, pw = args[0], args[1]
        elif len(args) == 7:
            self.un, pw, self.pub_key, self.priv_key, self.verify_key, self.sign_key, self.shared_files = \
                args[0], args[1], args[2], args[3], args[4], args[5], args[6]
        else:
            raise TypeError("Incorrect number of arguments for User")

        self.base_key = crypto.PasswordKDF(self.un+pw,
                                           crypto.HashKDF(util.ObjectToBytes(
                                               self.un+pw), "base_key_salt"),
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
            pub_key = keyserver.Get(username+"_pub_key")
            verify_key = keyserver.Get(username+"_verify_key")
        except ValueError:
            raise util.DropboxError(
                "Authentication Error- No such User exists.")

        # Locate and retrieve private/sign key
        try:
            priv_key_get = dataserver.Get(generate_memloc(
                self.base_key, username+"_priv_key_storage"))
        except:
            raise util.DropboxError(
                "Authentication Error- Check Your Username/Password!")
        try: 
            priv_key = crypto.AsymmetricDecryptKey.from_bytes(
                sym_decrypt(self.base_key, "_priv_key_storage", priv_key_get))
        except:
            raise util.DropboxError(
                "Authentication Error - Data tampered!"
            )

        try:
            sign_key_get = dataserver.Get(generate_memloc(
                self.base_key, username+"_sign_key_storage"))
        except:
            raise util.DropboxError(
                "Authentication Error- Check Your Username/Password!")
        sign_key = crypto.SignatureSignKey.from_bytes(
            sym_decrypt(self.base_key, "_sign_key_storage", sign_key_get))

        # Confirm encryption/decryption keys
        auth_msg = b"The Treaty of Versailles[4] was a peace treaty signed on 28 June 1919."
        enc_msg = crypto.AsymmetricEncrypt(pub_key, auth_msg)
        dec_msg = crypto.AsymmetricDecrypt(priv_key, enc_msg)

        if dec_msg != auth_msg:
            raise util.DropboxError(
                "Authentication Error- Check Your Username/Password!")

        # Confirm signature/verify keys
        sign_msg = crypto.SignatureSign(sign_key,
                                        enc_msg)
        verify_msg = crypto.SignatureVerify(verify_key, enc_msg, sign_msg)
        if verify_msg != True:
            raise util.DropboxError(
                "Authentication Error - Check Your Username/Password!")

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
        # if it's a shared file, retrieve the base_key; if it's yours, 
        if filename in self.shared_files.keys():
            sender = self.shared_files[filename]
            sharing_string = filename+"sharing_str_"+sender+"_"+self.un
            sharing_key = crypto.Hash(sharing_string.encode("utf-8"))[:16]
            sharing_memloc = generate_memloc(
                sharing_key, filename+"_sharing_loc_"+sender+"_"+self.un
            )
            sharing_dict_bytes = dataserver.Get(sharing_memloc)
            sharing_dict = util.BytesToObject(sharing_dict_bytes)
            file_elements = sharing_dict[filename]
            enc_file_key = file_elements[0]
            file_signature = file_elements[1]

            try:
                crypto.SignatureVerify(
                    keyserver.Get(sender+"_verify_key"),
                    enc_file_key,
                    file_signature
                )
            except:
                raise util.DropboxError("File integrity damaged.")
            
            # get the file base key
            base_key = crypto.AsymmetricDecrypt(self.priv_key, enc_file_key)

        else:
            try:
                dataserver.Get(generate_memloc(self.base_key, filename+"_master_key"))
            except:
                # generate base key for this file
                base_key = crypto.HashKDF(self.base_key, filename+crypto.SecureRandom(16).decode(errors='backslashreplace'))
                base_key_loc = generate_memloc(self.base_key, filename+"_master_key")

                # encrypt/store base key
                enc_base_key, _ = sym_enc_sign(self.base_key, filename+"_master_key", base_key)
                dataserver.Set(base_key_loc, enc_base_key)
        
        # slice file
        body, tail = slice_file(data)
        block_count = 2

        # check if we need to separate file into multiple blocks
        if body == tail:
            block_count = 1

        # initialize metadata: sharing list, block count
        share_list = util.ObjectToBytes([self.un])
        block_count_loc = generate_memloc(
            base_key, filename+"_num_blocks")
        share_list_loc = generate_memloc(base_key, filename+"_sharing")

        # encrypt and store metadata
        enc_num_blocks, _ = sym_enc_sign(
            base_key, filename+"_num_blocks", block_count.to_bytes(16, 'little'))
        enc_sharing, _ = sym_enc_sign(
            base_key, filename+"_sharing", share_list)
        dataserver.Set(block_count_loc, enc_num_blocks)
        dataserver.Set(share_list_loc, enc_sharing)

        # file slice memlocs
        body_loc = generate_memloc(base_key, f'{filename}_block_{0}')
        tail_loc = generate_memloc(base_key, f'{filename}_block_{1}')

        # encrypt + sign, store body (and tail if applicable)
        enc_body, _ = sym_enc_sign(
            base_key, f'{filename}_block_{0}', body)
        dataserver.Set(body_loc, enc_body)
        if block_count == 2:
            enc_tail, _ = sym_enc_sign(
                base_key, f'{filename}_block_{1}', tail)
            dataserver.Set(tail_loc, enc_tail)

    def download_file(self, filename: str) -> bytes:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/download-file.html
        """
        # get base_key
        try:
            base_key_loc = generate_memloc(
                self.base_key, filename+"_master_key")

            # decrypt base key
            enc_base_key = dataserver.Get(base_key_loc)
            base_key = sym_verify_dec(self.base_key, filename+"_master_key", enc_base_key)
        except ValueError:
            raise util.DropboxError("No such file found.")

        # get num_blocks
        try:
            block_count_loc = generate_memloc(
                base_key, filename+"_num_blocks")
            enc_block_count = dataserver.Get(block_count_loc)
            block_count = int.from_bytes(sym_verify_dec(
                base_key, filename+"_num_blocks", enc_block_count), "little")
        except ValueError:
            raise util.DropboxError("File metadata corrupted.")

        # iterate through all blocks and download them
        doc = bytes()
        for i in range(0, block_count):
            try:
                # retrieve block
                curr_loc = generate_memloc(
                    base_key, f'{filename}_block_{i}')
                curr_block = dataserver.Get(curr_loc)

                # decrypt and verify block - this function throws util.DropboxError if integrity violation is detected
                dec_block = sym_verify_dec(
                    base_key, f'{filename}_block_{i}', curr_block)
            except ValueError:
                raise util.DropboxError(
                    "File could not be found due to malicious action.")
            doc += dec_block

        return doc

    def append_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/append-file.html
        """
        # get base_key
        try:
            base_key_loc = generate_memloc(
                self.base_key, filename+"_master_key")

            # decrypt base key
            enc_base_key = dataserver.Get(base_key_loc)
            base_key = sym_verify_dec(
                self.base_key, filename+"_master_key", enc_base_key)
        except ValueError:
            raise util.DropboxError("No such file found.")

        # get num_blocks
        try:
            block_count_loc = generate_memloc(
                base_key, filename+"_num_blocks")
            enc_block_count = dataserver.Get(block_count_loc)
            block_count = int.from_bytes(sym_verify_dec(
                base_key, filename+"_num_blocks", enc_block_count), "little")
        except ValueError:
            # failed dataserver get - no filename found (likely)
            raise util.DropboxError("No such file found")

        # get last block
        try:
            # retrieve block
            last_block_loc = generate_memloc(
                base_key, f'{filename}_block_{block_count - 1}')
            last_block = dataserver.Get(last_block_loc)

            # decrypt and verify block - this function throws util.DropboxError if integrity violation is detected
            dec_block = sym_verify_dec(
                base_key, f'{filename}_block_{block_count - 1}', last_block)
        except ValueError:
            raise util.DropboxError(
                "File could not be found due to malicious action.")

        # combine and slice
        to_append = dec_block + data
        body, tail = slice_file(to_append)

        # memlocs
        body_loc = generate_memloc(
            base_key, f'{filename}_block_{block_count - 1}')

        # encrypt + sign, store body
        enc_body, _ = sym_enc_sign(
            base_key, f'{filename}_block_{block_count - 1}', body)
        dataserver.Set(body_loc, enc_body)

        
        # if slicing is necessary - increment block_count, store tail
        if body != tail:
            tail_loc = generate_memloc(
                base_key, f'{filename}_block_{block_count}')
            enc_tail, _ = sym_enc_sign(
                base_key, f'{filename}_block_{block_count}', tail)
            dataserver.Set(tail_loc, enc_tail)

            # increment number of blocks and re-store
            block_count += 1
            enc_num_blocks, _ = sym_enc_sign(
                base_key, filename+"_num_blocks", block_count.to_bytes(16, 'little'))
            dataserver.Set(block_count_loc, enc_num_blocks)

    def share_file(self, filename: str, recipient: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/share-file.html
        """
        # get base key for file
        try:
            base_key_loc = generate_memloc(
                self.base_key, filename+"_master_key"
            )

            enc_base_key = dataserver.Get(base_key_loc)
            base_key = sym_verify_dec(
                self.base_key, filename+"_master_key", enc_base_key)
        except ValueError:
            raise util.DropboxError("No such file found.")
        
        # generate memlocs for common access
        sharing_string = filename+"sharing_str_"+self.un+"_"+recipient
        sharing_key = crypto.Hash(sharing_string.encode("utf-8"))[:16]
        sharing_memloc = generate_memloc(
            sharing_key, filename+"_sharing_loc_"+self.un+"_"+recipient
        )

        # get recipient public key
        try:
            recipient_pub_key = keyserver.Get(recipient+"_pub_key")
        except ValueError:
            raise util.DropboxError("No such recipient found.")
        
        # create asymmetric key encryption and signature for base_key
        enc_file_base_key, sign_file_base_key = asym_enc_sign(
            recipient_pub_key, self.sign_key, base_key
            )
        
        # determine if there is already a dict between the two users; if not, create one
        try:
            dataserver.Get(sharing_memloc)
        except ValueError:
            dict = {}
            dict_bytes = util.ObjectToBytes(dict)
            dataserver.Set(sharing_memloc, dict_bytes)

        # add the encrypted key and the signature to dataserver
        sharing_dict_bytes = dataserver.Get(sharing_memloc)
        sharing_dict = util.BytesToObject(sharing_dict_bytes)
        sharing_dict[filename] = [enc_file_base_key, sign_file_base_key]
        sharing_dict_bytes = util.ObjectToBytes(sharing_dict)
        
        dataserver.Set(sharing_memloc, sharing_dict_bytes)

        # add the recipient to the file
        share_list_loc = generate_memloc(base_key, filename+"_sharing")
        share_list_bytes = sym_verify_dec(
            base_key, filename+"_sharing", dataserver.Get(share_list_loc)
            )
        share_list = util.BytesToObject(share_list_bytes)
        share_list.append(recipient)

        share_list_bytes = util.ObjectToBytes(share_list)
        share_list, _ = sym_enc_sign(
            base_key, filename+"_sharing", share_list_bytes)
        dataserver.Set(share_list_loc, share_list)


    def receive_file(self, filename: str, sender: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/receive-file.html
        """
        # find the sharing memloc
        sharing_string = filename+"sharing_str_"+sender+"_"+self.un
        sharing_key = crypto.Hash(sharing_string.encode("utf-8"))[:16]
        sharing_memloc = generate_memloc(
            sharing_key, filename+"_sharing_loc_"+sender+"_"+self.un
        )

        # attempt to retrieve dict
        try:
            sharing_dict_bytes = dataserver.Get(sharing_memloc)
        except ValueError:
            raise util.DropboxError("No such file shared by recipient.")
        
        # decrypt and verify
        sharing_dict = util.BytesToObject(sharing_dict_bytes)
        file_elements = sharing_dict[filename]
        enc_file_key = file_elements[0]
        file_signature = file_elements[1]

        try:
            crypto.SignatureVerify(
                keyserver.Get(sender+"_verify_key"),
                enc_file_key,
                file_signature
            )
        except:
            raise util.DropboxError("File integrity damaged.")
        
        # get the file base key
        file_key = crypto.AsymmetricDecrypt(self.priv_key, enc_file_key)

        # store this file base key for this user
        base_key_loc = generate_memloc(
                self.base_key, filename+"_master_key")
        enc_base_key, _ = sym_enc_sign(self.base_key, filename+"_master_key", file_key)
        dataserver.Set(base_key_loc, enc_base_key)

        # add to shared_files in User object
        self.shared_files[filename] = sender


    def revoke_file(self, filename: str, old_recipient: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/revoke-file.html
        """
        
        pass


def slice_file(data: bytes) -> tuple[bytes, bytes]:
    """
    Splits a given file into a body and tail consisting of the last 16 bytes of the file.
    If the file is less than 16 bytes long, just returns the entire file for both outputs

    Parameters:
        - data: data to be sliced
    Returns:
        - body: the entirety of the file, minus the last 16 bytes of the file.
        - tail: the last 16 bytes of the file.
    """
    size = len(data)

    # data is smaller than 16 bytes - no need to slice
    if size <= 16:
        return data, data

    # take at most the last 16 bytes
    tail_size = size % 16 if size % 16 != 0 else 16
    body = data[0:size - tail_size]
    tail = data[size - tail_size:size]

    return body, tail


def encrypt(base_key: bytes, purpose: str, data: bytes) -> bytes:
    """
    Derives a new key from the base_key to encrypt the given data

    Parameters:
        - base_key: the base key to be used with HashKDF, unique to each user
        - purpose: the purpose to be used with HashKDF, describing the data being encrypted
        - data: the data being encrypted
    Returns:
        - the data encrypted symmetrically with a key derived from the given base key and purpose.
    """
    enc_key = crypto.HashKDF(base_key, purpose+"_sym_enc")
    enc_data = crypto.SymmetricEncrypt(enc_key, crypto.SecureRandom(16), data)
    return enc_data


def sym_decrypt(base_key: bytes, purpose: str, data: bytes) -> bytes:
    """
    Derives a new key from the base_key to decrypt the given data.

    Parameters:
        - base_key: the base key to be used with HashKDF, unique to each user
        - purpose: the purpose to be used with HashKDF, describing the data being decrypted
        - data: the data being decrypted
    Returns:
        - the data decrypted symmetrically with a key derived from the given base key and purpose.
    """
    enc_key = crypto.HashKDF(base_key, purpose+"_sym_enc")
    dec_data = crypto.SymmetricDecrypt(enc_key, data)
    return dec_data


def sym_hmac(base_key: bytes, purpose: str, data: bytes) -> bytes:
    """
    Generates an HMAC for the given data. Must only be called on data that has already been
    encrypted with a different key.

    Parameters:
        - base_key: the base key to be used with HashKDF, unique to each user
        - purpose: the purpose to be used with HashKDF, describing the data being HMAC'ed
        - data: the data being HMAC'ed. Must be encrypted symmetrically beforehand using a different key.
    Returns:
        - the HMAC of the data with a key derived from the given base key and purpose.
    """
    sign_key = crypto.HashKDF(base_key, purpose+"_sym_sign")
    hmac = crypto.HMAC(sign_key, data)
    return hmac


def sym_enc_sign(base_key: bytes, purpose: str, data: bytes) -> None:
    """
    Derives a new key from the base_key to encrypt the given data, then HMACs the encrypted data
    and stores the HMAC in the dataserver (encrypt-then-MAC). Should be used for most storage purposes.

    Parameters:
        - base_key: the base key to be used with HashKDF, unique to each user
        - purpose: the purpose to be used with HashKDF, describing the data being encrypted
        - data: the data being encrypted
    Returns:
        - enc_data: the data encrypted symmetrically with a key derived from the given base key and purpose.
        - hmac: the HMAC of the encrypted data. 
    """
    enc_data = encrypt(base_key, purpose, data)
    hmac = sym_hmac(base_key, purpose, enc_data)
    dataserver.Set(generate_memloc(base_key, purpose+"_hmac_store"), hmac)
    return enc_data, hmac


def sym_verify_dec(base_key: bytes, purpose: str, data: bytes) -> bytes:
    """
    HMACs the encrypted dataand comapres the generated HMAC with the corresponding HMAC stored
    on the dataserver. Raises an error if an integrity violation is detected or returns the decrypted
    data if no violation is detected. Should be used for most retrieval purposes.

    Parameters:
        - base_key: the base key to be used with HashKDF, unique to each user
        - purpose: the purpose to be used with HashKDF, describing the data being decrypted
        - data: the data being decrypted
    Raises:
        - util.DropboxError if the stored and generated HMACs do not match.
    Returns:
        - the data decrypted symmetrically with a key derived from the given base key and purpose.
    """
    hmac = sym_hmac(base_key, purpose, data)
    try:
        stored_hmac = dataserver.Get(
            generate_memloc(base_key, purpose+"_hmac_store"))
    except ValueError:
        util.DropboxError("No signature stored")

    if not crypto.HMACEqual(hmac, stored_hmac):
        util.DropboxError("Integrity error - HMAC could not be verified")

    dec_data = sym_decrypt(base_key, purpose, data)

    return dec_data


def generate_memloc(base_key: bytes, purpose: str) -> memloc:
    """
    Generates a memloc for the given purpose from the given base_key using HashKDF.

    Parameters:
        - base_key: the base key to be used with HashKDF, unique to each user
        - purpose: the purpose to be used with HashKDF, describing the data being stored
    Returns:
        - a unique Memloc generated from the given base_key and purpose
    """
    bytestring = crypto.HashKDF(base_key, purpose+"_memloc")
    return memloc.MakeFromBytes(bytestring)

def asym_enc_sign(enc_key: crypto.AsymmetricEncryptKey, 
                  sign_key: crypto.SignatureSignKey, data: bytes) -> None:
    """
    Asymmetrically encrypts and then digitally signs some data.

    Parameters:
        - enc_key: the assymetric encryption key
        - sign_key: the digital signature key
        - data: the data to encrypt and sign
    """
    enc_data = crypto.AsymmetricEncrypt(enc_key, data)
    sign_data = crypto.SignatureSign(sign_key, enc_data)
    return enc_data, sign_data

def update_key(self: User, filename: str) -> None:
    """
    Given a User object and a filename, if the 
    """

def create_user(username: str, password: str) -> User:
    """
    The specification for this function is at:
    http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/authentication/create-user.html
    """
    # Initialize necessary keys
    pub_key, priv_key = crypto.AsymmetricKeyGen()
    verify_key, sign_key = crypto.SignatureKeyGen()
    shared_files = dict()

    # Initialize User object
    current_user = User(username, password, pub_key,
                        priv_key, verify_key, sign_key, shared_files)

    # Check if username is already taken, or is empty string
    if username == "":
        raise util.DropboxError("Usernames cannot be empty.")

    try:
        keyserver.Get(username+"_pub_key")
    except ValueError:  # if no entry with the same username exists in keyserver, we may continue
        pass
    else:
        raise util.DropboxError(
            "Username already exists; please choose a new username.")

    # Store public keys in the Keyserver
    keyserver.Set(username+"_pub_key",
                  pub_key)
    keyserver.Set(username+"_verify_key",
                  verify_key)

    # Store private keys in the Dataserver
    dataserver.Set(generate_memloc(current_user.base_key, username+"_priv_key_storage"),
                   encrypt(current_user.base_key,
                           "_priv_key_storage", bytes(priv_key))
                   )
    dataserver.Set(generate_memloc(current_user.base_key, username+"_sign_key_storage"),
                   encrypt(current_user.base_key,
                           "_sign_key_storage", bytes(sign_key))
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


# u = create_user("bob", "pw")
# authenticate_user("bob", "pw")
# u.upload_file("filename", b'hello')
# u.upload_file("filename2", b'hello my name is bob this is a long file.')
# u.upload_file("emptyfile", b'')
# # authenticate_user("bob", "sw")

u = create_user("John", "pw")
u2 = create_user("Paul", "pw")
u.upload_file("filename", b"file_contents")
u.share_file("filename", "Paul")
u2.receive_file("filename", "John")
u2.upload_file("filename", b"file_other")
u
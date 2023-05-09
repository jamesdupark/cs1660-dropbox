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
            - shared_files: dictionary - stores filenames and owners of files shared to the User
        Fields:
            - un: str - username of the User
            - base_key - base key of the User, used to generate other symmetric keys and memlocs
            - pub_key: crypto.AsymmetricEncryptKey - public encryption key of the User
            - priv_key: crypto.AsymmetricDecryptKey - private decryption key of the User
            - verify_key: crypto.SignatureVerifyKey - public verification key of the User
            - sign_key: crypto.SignatureSignKey - private signature key of the User
            - shared_files: dictionary - stores filenames and owners of files shared to the User
        """
        if len(args) == 2:
            self.un, pw = args[0], args[1]
        elif len(args) == 7:
            self.un, pw, self.pub_key, self.priv_key, self.verify_key, self.sign_key, self.shared_files = \
                args[0], args[1], args[2], args[3], args[4], args[5], args[6]
        else:
            raise TypeError("Incorrect number of arguments for User")

        # generate base key
        self.base_key = crypto.PasswordKDF(self.un+pw,
                                           crypto.HashKDF(util.ObjectToBytes(
                                               self.un+pw), "base_key_salt"),
                                           16)

        self.shared_files = dict()
        # create and push empty shared file dict to the dataserver
        shared_file_loc = generate_memloc(self.base_key, "shared_file_dict")
        shared_file_bytes = util.ObjectToBytes(self.shared_files)
        enc_shared_files, _ = sym_enc_sign(
            self.base_key, "shared_file_dict", shared_file_bytes)
        dataserver.Set(shared_file_loc, enc_shared_files)

        self.shared_with = dict()
        # create and push empty shared with dict to dataserver
        shared_with_loc = generate_memloc(self.base_key, "shared_with_dict")
        shared_with_bytes = util.ObjectToBytes(self.shared_with)
        enc_shared_with, _ = sym_enc_sign(
            self.base_key, "shared_with_dict", shared_with_bytes)
        dataserver.Set(shared_with_loc, enc_shared_with)

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

        # pull shared files from dataserver
        try:
            shared_file_loc = generate_memloc(
                self.base_key, "shared_file_dict")
            enc_shared_file_bytes = dataserver.Get(shared_file_loc)
            dec_shared_file_bytes = sym_verify_dec(
                self.base_key, "shared_file_dict", enc_shared_file_bytes)
            shared_file_dict = util.BytesToObject(dec_shared_file_bytes)
        except ValueError:
            raise util.DropboxError("No shared files dictionary found!")

        # pull shared_with dict from dataserver
        try:
            shared_w_loc = generate_memloc(self.base_key, "shared_with_dict")
            enc_shared_w_bytes = dataserver.Get(shared_w_loc)
            dec_shared_file_bytes = sym_verify_dec(
                self.base_key, "shared_with_dict", enc_shared_w_bytes)
            shared_with = util.BytesToObject(dec_shared_file_bytes)
        except ValueError:
            raise util.DropboxError("No shared files dictionary found!")

        # keys have been verified, assign to fields
        self.pub_key = pub_key
        self.priv_key = priv_key
        self.verify_key = verify_key
        self.sign_key = sign_key
        self.shared_files = shared_file_dict
        self.shared_with = shared_with

    def upload_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/upload-file.html
        """

        # check if a file_key already exists; if so, use the same one. if not, make new file_key
        try:
            file_key_loc = generate_memloc(
                self.base_key, filename+"_master_key")
            file_key = sym_verify_dec(
                self.base_key, filename +
                "_master_key", dataserver.Get(file_key_loc)
            )
        except ValueError:
            # generate file key for this file
            file_key = crypto.HashKDF(
                self.base_key, filename+crypto.SecureRandom(16).decode(errors='backslashreplace'))
            # encrypt & store file key
            enc_file_key, _ = sym_enc_sign(
                self.base_key, filename+"_master_key", file_key)
            dataserver.Set(file_key_loc, enc_file_key)

            # generate metadata
            meta = dict()
            meta["current"] = True
        else:
            # download metadata
            meta_loc = generate_memloc(file_key, "metadata")
            enc_meta = dataserver.Get(meta_loc)
            meta_bytes = sym_verify_dec(file_key, "metadata", enc_meta)
            meta = util.BytesToObject(meta_bytes)

        # slice file
        body, tail = slice_file(data)
        block_count = 2

        # check if we need to separate the file into multiple blocks
        if body == tail:
            block_count = 1

        if not meta["current"]:
            # call recieve_file as necessary or fail b/c you've been revoked --> remove from shared_files
            self.receive_file(filename, self.shared_files[filename])
            self.upload_file(filename, data)
            return

        meta["block_count"] = block_count

        meta_loc = generate_memloc(file_key, "metadata")
        enc_meta, _ = sym_enc_sign(
            file_key, "metadata", util.ObjectToBytes(meta))
        dataserver.Set(meta_loc, enc_meta)

        # file slice memlocs
        body_loc = generate_memloc(file_key, f'{filename}_block_{0}')
        tail_loc = generate_memloc(file_key, f'{filename}_block_{1}')

        # encrypt & sign, store body (and tail if applicable)
        enc_body, _ = sym_enc_sign(
            file_key, f'{filename}_block_{0}', body)
        dataserver.Set(body_loc, enc_body)

        if block_count == 2:
            enc_tail, _ = sym_enc_sign(
                file_key, f'{filename}_block_{1}', tail)
            dataserver.Set(tail_loc, enc_tail)

    def download_file(self, filename: str) -> bytes:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/download-file.html
        """

        # get file_key
        try:
            file_key_loc = generate_memloc(
                self.base_key, filename+"_master_key")

            # decrypt base key
            enc_file_key = dataserver.Get(file_key_loc)
            file_key = sym_verify_dec(
                self.base_key, filename+"_master_key", enc_file_key)
        except ValueError:
            raise util.DropboxError("No such file found.")

        # get metadata
        try:
            meta_loc = generate_memloc(file_key, "metadata")
            enc_meta = dataserver.Get(meta_loc)
            meta_bytes = sym_verify_dec(file_key, "metadata", enc_meta)
            meta = util.BytesToObject(meta_bytes)

            block_count = meta["block_count"]
        except ValueError:
            raise util.DropboxError("File metadata corrupted.")

        if not meta["current"]:
            # call recieve_file as necessary or fail b/c you've been revoked --> remove from shared_files
            self.receive_file(filename, self.shared_files[filename])
            return self.download_file(filename)

        # iterate through all blocks and download them
        doc = bytes()
        for i in range(0, block_count):
            try:
                # retrieve block
                curr_loc = generate_memloc(
                    file_key, f'{filename}_block_{i}')
                curr_block = dataserver.Get(curr_loc)

                # decrypt and verify block - this function throws util.DropboxError if integrity violation is detected
                dec_block = sym_verify_dec(
                    file_key, f'{filename}_block_{i}', curr_block)
            except ValueError:
                raise util.DropboxError(
                    "File could not be found due to malicious action."
                )

            doc += dec_block

        return doc

    def append_file(self, filename: str, data: bytes) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/storage/append-file.html
        """

        # get file_key
        try:
            file_key_loc = generate_memloc(
                self.base_key, filename+"_master_key")

            # decrypt file key
            enc_file_key = dataserver.Get(file_key_loc)
            file_key = sym_verify_dec(
                self.base_key, filename+"_master_key", enc_file_key)
        except ValueError:
            raise util.DropboxError("No such file found.")

        # get metadata
        try:
            # download metadata
            meta_loc = generate_memloc(file_key, "metadata")
            enc_meta = dataserver.Get(meta_loc)
            meta_bytes = sym_verify_dec(file_key, "metadata", enc_meta)
            meta = util.BytesToObject(meta_bytes)

            block_count = meta["block_count"]
        except ValueError:
            # failed dataserver get - no filename found (likely)
            raise util.DropboxError("No such file found")

        # if current = False, update
        if not meta["current"]:
            # call recieve_file as necessary or fail b/c you've been revoked --> remove from shared_files
            self.receive_file(filename, self.shared_files[filename])
            self.append_file(filename, data)
            return

        # get last block
        try:
            # retrieve block
            last_block_loc = generate_memloc(
                file_key, f'{filename}_block_{block_count - 1}')
            last_block = dataserver.Get(last_block_loc)

            # decrypt and verify block - this function throws util.DropboxError if integrity violation is detected
            dec_block = sym_verify_dec(
                file_key, f'{filename}_block_{block_count - 1}', last_block)
        except ValueError:
            raise util.DropboxError(
                "File could not be found due to malicious action.")

        # combine and slice
        to_append = dec_block + data
        body, tail = slice_file(to_append)

        # memlocs
        body_loc = generate_memloc(
            file_key, f'{filename}_block_{block_count - 1}')

        # encrypt + sign, store body
        enc_body, _ = sym_enc_sign(
            file_key, f'{filename}_block_{block_count - 1}', body)
        dataserver.Set(body_loc, enc_body)

        # if slicing is necessary - increment block_count, store tail
        if body != tail:
            tail_loc = generate_memloc(
                file_key, f'{filename}_block_{block_count}')
            enc_tail, _ = sym_enc_sign(
                file_key, f'{filename}_block_{block_count}', tail)
            dataserver.Set(tail_loc, enc_tail)

            # increment number of blocks and re-store metadata
            block_count += 1
            meta["block_count"] = block_count
            meta_loc = generate_memloc(file_key, "metadata")
            enc_meta, _ = sym_enc_sign(
                file_key, "metadata", util.ObjectToBytes(meta))
            dataserver.Set(meta_loc, enc_meta)

    def share_file(self, filename: str, recipient: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/share-file.html
        """
        # find filename's file_key
        try:
            file_key_loc = generate_memloc(
                self.base_key, filename+"_master_key")
            enc_file_key = dataserver.Get(file_key_loc)
            file_key = sym_verify_dec(
                self.base_key, filename+"_master_key", enc_file_key)
        except ValueError:
            raise util.DropboxError("No such file found.")

        # check for duplicate share
        try:
            shared_w_loc = generate_memloc(self.base_key, "shared_with_dict")
            enc_shared_w_bytes = dataserver.Get(shared_w_loc)
            dec_shared_file_bytes = sym_verify_dec(
                self.base_key, "shared_with_dict", enc_shared_w_bytes)
            self.shared_with = util.BytesToObject(dec_shared_file_bytes)
        except ValueError:
            raise util.DropboxError("shared_with dictionary not found!")

        # generate common memloc
        sharing_string = filename+"_sharing_"+self.un+"_"+recipient
        sharing_string_sign = filename+"_sharing_"+self.un+"_"+recipient+"_signature"
        sharing_key = crypto.Hash(sharing_string.encode("utf-8"))[:16]
        shared_dict_loc = generate_memloc(sharing_key, sharing_string)
        shared_dict_sign_loc = generate_memloc(sharing_key, sharing_string_sign)

        # get recipient pub_key
        try:
            recipient_pub_key = keyserver.Get(recipient+"_pub_key")
        except ValueError:
            raise util.DropboxError("No such recipient found.")
        
        # determine if there is a shared dict already; if not, create
        try:
            dataserver.Get(shared_dict_loc)
        except ValueError:
            shared_dict_bytes = util.ObjectToBytes(dict())
            
            enc_shared_dict, enc_shared_sign = asym_enc_sign(
                recipient_pub_key, self.sign_key, shared_dict_bytes
            )
            dataserver.Set(shared_dict_loc, enc_shared_dict)
            dataserver.Set(shared_dict_sign_loc, enc_shared_sign)

        # add file_key and file_signature to shared_dict_loc
        shared_dict = dict()
        shared_dict[filename] = [file_key]
        shared_dict_bytes = util.ObjectToBytes(shared_dict)
        enc_shared_dict, enc_shared_sign = asym_enc_sign(
            recipient_pub_key, self.sign_key, shared_dict_bytes)
        dataserver.Set(shared_dict_loc, enc_shared_dict)
        dataserver.Set(shared_dict_sign_loc, enc_shared_sign)

        # add recipient to file sharing metadata

        # update shared_with
        if filename in self.shared_with.keys():
            if recipient not in self.shared_with[filename]:
                self.shared_with[filename].append(recipient)
        else:
            self.shared_with[filename] = [recipient]

        # update shared_with on dataserver
        shared_with_loc = generate_memloc(
            self.base_key, "shared_with_dict")
        shared_with_bytes = util.ObjectToBytes(self.shared_with)
        enc_shared_with, _ = sym_enc_sign(
            self.base_key, "shared_with_dict", shared_with_bytes)
        dataserver.Set(shared_with_loc, enc_shared_with)

    def receive_file(self, filename: str, sender: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/receive-file.html
        """
        # retrieve file_key, if it exists
        try:
            sharing_string = filename+"_sharing_"+sender+"_"+self.un
            sharing_key = crypto.Hash(sharing_string.encode("utf-8"))[:16]
            shared_dict_loc = generate_memloc(sharing_key, sharing_string)
            enc_shared_dict = dataserver.Get(shared_dict_loc)

            sharing_string_sign = filename+"_sharing_"+sender+"_"+self.un+"_signature"
            shared_dict_sign_loc = generate_memloc(sharing_key, sharing_string_sign)
            shared_dict_bytes = asym_verify_dec(
                self.priv_key, keyserver.Get(sender+"_verify_key"), 
                dataserver.Get(shared_dict_sign_loc), enc_shared_dict)
            shared_dict = util.BytesToObject(shared_dict_bytes)
            
            if len(shared_dict[filename]) == 0:
                raise util.DropboxError("File has been revoked!")
        except ValueError:
            raise util.DropboxError("No such file shared with "+self.un+".")

        file_key_loc = generate_memloc(self.base_key, filename+"_master_key")
        # check for duplicate file
        try:
            enc_key = dataserver.Get(file_key_loc)
            file_key = sym_verify_dec(self.base_key, filename+"_master_key", enc_key)

            # get metadata
            try:
                # download metadata
                meta_loc = generate_memloc(file_key, "metadata")
                enc_meta = dataserver.Get(meta_loc)
                meta_bytes = sym_verify_dec(file_key, "metadata", enc_meta)
                meta = util.BytesToObject(meta_bytes)
            except ValueError:
                raise util.DropboxError("No such file found")
        except ValueError:
            # no duplicate, can proceed
            pass
        else:
            if meta["current"]:
                # not updating key
                raise util.DropboxError(
                    "file with name: "+filename+" already exists!")

        # retrieve file_key and file_signature
        file_key = shared_dict[filename][0]

        enc_file_key, _ = sym_enc_sign(
            self.base_key, filename+"_master_key", file_key
        )        
        dataserver.Set(file_key_loc, enc_file_key)

        # set User object to reflect new file
        self.shared_files[filename] = sender

        # push shared_file dict to dataserver
        shared_file_loc = generate_memloc(self.base_key, "shared_file_dict")
        shared_file_bytes = util.ObjectToBytes(self.shared_files)
        enc_shared_files, _ = sym_enc_sign(
            self.base_key, "shared_file_dict", shared_file_bytes)
        dataserver.Set(shared_file_loc, enc_shared_files)

    def revoke_file(self, filename: str, old_recipient: str) -> None:
        """
        The specification for this function is at:
        http://cs.brown.edu/courses/csci1660/dropbox-wiki/client-api/sharing/revoke-file.html
        """
        # go to old metadata and set "current" to false and remove the user from the share list
        # get flie key
        try:
            file_key_loc = generate_memloc(
                self.base_key, filename+"_master_key")
            enc_file_key = dataserver.Get(file_key_loc)
            file_key = sym_verify_dec(
                self.base_key, filename+"_master_key", enc_file_key)
        except ValueError:
            raise util.DropboxError("No such file found.")

        # download old file
        data = self.download_file(filename)

        # modify "current" to be False on the old metadata
        try:
            meta_loc = generate_memloc(file_key, "metadata")
            enc_meta = dataserver.Get(meta_loc)
            meta_bytes = sym_verify_dec(file_key, "metadata", enc_meta)
            meta = util.BytesToObject(meta_bytes)

            meta["current"] = False

            meta_loc = generate_memloc(file_key, "metadata")
            enc_meta, _ = sym_enc_sign(
                file_key, "metadata", util.ObjectToBytes(meta))
            dataserver.Set(meta_loc, enc_meta)
        except ValueError:
            raise util.DropboxError("File metadata corrupted.")

        # create a new base key and store it at our memloc for the file's master key
        new_file_key = crypto.HashKDF(
            self.base_key, filename+crypto.SecureRandom(16).decode(errors='backslashreplace'))
        # encrypt & store file key
        enc_file_key, _ = sym_enc_sign(
            self.base_key, filename+"_master_key", new_file_key)
        dataserver.Set(file_key_loc, enc_file_key)

        # initialize metadata; then store
        meta = dict()
        meta["current"] = True
        meta["block_count"] = 0
        meta_loc = generate_memloc(new_file_key, "metadata")
        enc_meta, _ = sym_enc_sign(
            new_file_key, "metadata", util.ObjectToBytes(meta))
        dataserver.Set(meta_loc, enc_meta)

        # remove the key from the user's shared_with dict
        # pull shared_with
        try:
            shared_w_loc = generate_memloc(self.base_key, "shared_with_dict")
            enc_shared_w_bytes = dataserver.Get(shared_w_loc)
            dec_shared_file_bytes = sym_verify_dec(
                self.base_key, "shared_with_dict", enc_shared_w_bytes)
            self.shared_with = util.BytesToObject(dec_shared_file_bytes)
        except ValueError:
            raise util.DropboxError("shared_with dictionary not found!")

        # remove from shared_with
        self.shared_with[filename].remove(old_recipient)

        # update shared_with on dataserver
        shared_with_bytes = util.ObjectToBytes(self.shared_with)
        enc_shared_with, _ = sym_enc_sign(
            self.base_key, "shared_with_dict", shared_with_bytes)
        dataserver.Set(shared_w_loc, enc_shared_with)

        # remove from shared dict
        try:
            sharing_string = filename+"_sharing_"+self.un+"_"+old_recipient
            sharing_key = crypto.Hash(sharing_string.encode("utf-8"))[:16]
            shared_dict_loc = generate_memloc(sharing_key, sharing_string)

            shared_dict = dict()
            shared_dict[filename] = []

            # push to shared_dict_loc
            shared_dict_bytes = util.ObjectToBytes(shared_dict)
            enc_shared_dict, _ = asym_enc_sign(
                keyserver.Get(old_recipient+"_pub_key"), self.sign_key,
                shared_dict_bytes)
            dataserver.Set(shared_dict_loc, enc_shared_dict)
        except ValueError:
            raise util.DropboxError("No such file shared with "+self.un+".")

        # call upload_flie on the key
        self.upload_file(filename, data)

        # call share_file on the file for each user in the shared list
        for recipient in self.shared_with[filename]:
            self.share_file(filename, recipient)


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


def asym_enc_sign(enc_key: crypto.AsymmetricEncryptKey,
                  sign_key: crypto.SignatureSignKey, data: bytes) -> tuple[bytes, bytes]:
    """
    Asymmetrically encrypts and then digitally signs some data.
    Parameters:
        - enc_key: the assymetric encryption key
        - sign_key: the digital signature key
        - data: the data to encrypt and sign
    Returns;
        - a tuple containing the data encrypted by enc_key, and a signature using the sign_key
    """
    enc_data = crypto.AsymmetricEncrypt(enc_key, data)
    sign_data = crypto.SignatureSign(sign_key, enc_data)
    return enc_data, sign_data


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

def asym_verify_dec(priv_key: bytes, verify_key: bytes, signature: bytes, data: bytes) -> bytes:
    """
    Given some data, a private key, and a verify key, attempts to asymmetrically
    decrypt and verify the data.

    Parameters:
        - priv_key: an asymmetric private key
        - verify_key: a verification key
        - signature: the signature to verify
        - data: some encrypted data
    Raises:
        - util.DropboxError if verification fails
    Returns:
        - the decrypted data
    """
    if crypto.SignatureVerify(verify_key, data, signature) == False:
        raise util.DropboxError("File metadata corrupted.")
    dec_data = crypto.AsymmetricDecrypt(priv_key, data)
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
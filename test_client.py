##
# test_client.py - Test for your client
##
##

import unittest
import string

import support.crypto as crypto
import support.util as util

from support.dataserver import dataserver, memloc
from support.keyserver import keyserver

# Import your client
import client as c

# Use this in place of the above line to test using the reference client
# import dropbox_client_reference as c


class ClientTests(unittest.TestCase):
    def setUp(self):
        """
        This function is automatically called before every test is run. It
        clears the dataserver and keyserver to a clean state for each test case.
        """
        dataserver.Clear()
        keyserver.Clear()

    def test_create_user(self):
        """
        Checks user creation.
        """
        u = c.create_user("usr", "pswd")
        u2 = c.authenticate_user("usr", "pswd")

        self.assertEqual(vars(u), vars(u2))

    def test_upload(self):
        """
        Tests if uploading a file throws any errors.
        """
        u = c.create_user("usr", "pswd")
        u.upload_file("file1", b'testing data')

    def test_download(self):
        """
        Tests if a downloaded file has the correct data in it.
        """
        u = c.create_user("usr", "pswd")

        data_to_be_uploaded = b'testing data'

        u.upload_file("file1", data_to_be_uploaded)
        downloaded_data = u.download_file("file1")

        self.assertEqual(downloaded_data, data_to_be_uploaded)

    def test_share_and_download(self):
        """
        Simple test of sharing and downloading a shared file.
        """
        u1 = c.create_user("usr1", "pswd")
        u2 = c.create_user("usr2", "pswd")
        u3 = c.create_user("usr3", "pswd")

        u1.upload_file("shared_file", b'shared data')
        u1.share_file("shared_file", "usr2")
        u1.share_file("shared_file", "usr3")

        u2.receive_file("shared_file", "usr1")
        u3.receive_file("shared_file", "usr1")
        down_data = u2.download_file("shared_file")

        self.assertEqual(down_data, b'shared data')

        u1.revoke_file("shared_file", "usr2")

        data_2 = u3.download_file("shared_file")
        self.assertEqual(data_2, b'shared data')
        self.assertRaises(util.DropboxError,
                          lambda: u2.download_file("shared_file"))

    def test_download_error(self):
        """
        Simple test that tests that downloading a file that doesn't exist
        raise an error.
        """
        u = c.create_user("usr", "pswd")

        # NOTE: When using `assertRaises`, the code that is expected to raise an
        #       error needs to be passed to `assertRaises` as a lambda function.
        self.assertRaises(util.DropboxError, lambda: u.download_file("file1"))

    def test_create_user(self):
        """
        Tests to ensure create_user() meets conditions as specified on wiki.
        """
        # Case sensitive usernames:
        user_1 = c.create_user("John", "yoko")
        self.assertRaises(util.DropboxError,
                          lambda: c.create_user("John", "yoko_ono"))

        # Users may choose the same password:
        user_2 = c.create_user("Paul", "yoko")
        user_3 = c.create_user("George", "yoko")

    def test_authenticate_user(self):
        """
        Tests to ensure authenticate_user meets conditions as specified on wiki.
        """
        # create two users
        u1 = c.create_user("John", "pw")
        u2 = c.create_user("Paul", "pw")

        # authenticate w/ same un/pw should work
        u1a = c.authenticate_user("John", "pw")
        self.assertEqual(vars(u1), vars(u1a))
        u2a = c.authenticate_user("Paul", "pw")
        self.assertEqual(vars(u2), vars(u2a))

        # if un/pw is wrong or doesn't exist, authentication fails
        self.assertRaises(util.DropboxError,
                          lambda: c.authenticate_user("John", "pww"))
        self.assertRaises(util.DropboxError,
                          lambda: c.authenticate_user("Paul", "pwe"))
        self.assertRaises(util.DropboxError,
                          lambda: c.authenticate_user("Ringo", "pw"))

    def test_the_next_test(self):
        """
        Implement more tests by defining more functions like this one!

        Functions have to start with the word "test" to be recognized. Refer to
        the Python `unittest` API for more information on how to write test
        cases: https://docs.python.org/3/library/unittest.html
        """
        self.assertTrue(True)

    def test_auth_overwrite(self):
        """
        Testing the first attack described in our design document - malicious user overwrites
        another user's private keys - our system detects the integrity violation and raises an error
        """
        # create user
        u1 = c.create_user("Bob", "pw")

        # get the locations of the private keys
        priv_key_loc = c.generate_memloc(
            u1.base_key, u1.un+"_priv_key_storage")
        sign_key_loc = c.generate_memloc(
            u1.base_key, u1.un+"_sign_key_storage")

        # generate malicious user
        u2 = c.create_user("Eve", "password")

        # replace sign keys with Eve's keys
        dataserver.Set(priv_key_loc, bytes(u2.priv_key))
        dataserver.Set(sign_key_loc, bytes(u2.sign_key))

        # authenticating as Bob throws an error
        self.assertRaises(util.DropboxError,
                          lambda: c.authenticate_user("Bob", "pw"))

    def test_false_revocation(self):
        """
        testing the second attack described in our design document - malicious user forges
        a false sharing dictionary so that the system thinks the recipient has been revoked.
        Our system detects this as an integrity violation and moves on
        """
        # create two normal users
        u1 = c.create_user("Bob", "pw")
        u2 = c.create_user("Alice", "pw")

        # u1 shares a file w/u2
        u1.upload_file("f", b'')
        u1.share_file("f", "Alice")

        # attacker modifies sharing dictionary
        sharing_string = "f"+"_sharing_"+u1.un+"_"+u2.un
        sharing_key = crypto.Hash(sharing_string.encode("utf-8"))[:16]
        shared_dict_loc = c.generate_memloc(
            sharing_key, sharing_string
        )
        mal_dict = { "f" : [] }
        mal_dict_bytes = util.ObjectToBytes(mal_dict)
        dataserver.Set(shared_dict_loc, mal_dict_bytes)

        # receiving throws an error
        self.assertRaises(util.DropboxError, lambda: u2.receive_file("f", "Bob"))

    def test_file_metadata_manipulation(self):
        """
        testing our third attack described in our design document - the adversary forges
        file data by overwriting it with some other data in the dataserver, hoping that 
        when a user downloads said file, they download her data instead 
        """
        # create a user and a file
        u1 = c.create_user("Paul", "somepass")
        u1.upload_file("file1", b"something")

        # for reference
        file1_key = c.sym_verify_dec(
            u1.base_key, "file1_master_key", 
            dataserver.Get(c.generate_memloc(u1.base_key, "file1_master_key"))
        )
        file1_metadata_loc = c.generate_memloc(file1_key, "metadata")

        # create an attacker and a "virus" to be placed in the metadata location
        opp = c.create_user("John", "pass")
        virus, _ = c.sym_enc_sign(
            opp.base_key, "file1_block_0", c.util.ObjectToBytes({"block_count": 2})
        )
        dataserver.Set(file1_metadata_loc, virus)

        # the attacker then adds their own special block at a location where download_file()
        # might eventually reach

        file1_eventual_block_loc = c.generate_memloc(file1_key, f'file1_block_{1}')
        dataserver.Set(file1_eventual_block_loc, b"an attack!")

        # the block_count should strictly be 1, as the original uploaded_file was not
        # large enough to warrant slicing, but the attacker is trying to set it at
        # 2 so that a user will download a file that would thero    

        # metadata corrupted, throw an error!
        self.assertRaises(util.DropboxError, lambda: u1.download_file("file1"))
    
    def test_unshared_receive(self):
        """
        testing our fourth attack described in our design document - the adversary somehow figures
        out a filename and the username of its owner, and attempts to call receieve_file().
        In addition, the adversary manages to figure out the location of the shared dictionary
        between two users for a shared file, but is unable to access it because it is
        asymmetrically encrypted using the intended recipient's public key- tampering this dict
        would also result in an integrity violation and a DropboxError for the recipient.
        """
        # create two normal users
        u1 = c.create_user("Bob", "pw")
        u2 = c.create_user("Joan", "bw")

        # adversary
        opp = c.create_user("John", "pw")

        # create a file
        u1.upload_file("BoTT", b"Shelter")

        # adversary attempts to access knowing the owner + filename, but fails
        self.assertRaises(util.DropboxError, lambda: opp.receive_file("BoTT", "Bob"))

        # adversary figures out the memloc of a shared_dict between two users
        u1.share_file("BoTT", "Joan")
        u2.receive_file("BoTT", "Bob")

        
        sharing_string = "BoTT"+"_sharing_"+"Bob"+"_"+"Joan"
        sharing_key = crypto.Hash(sharing_string.encode("utf-8"))[:16]
        shared_dict_loc = c.generate_memloc(sharing_key, sharing_string)
        enc_shared_dict = dataserver.Get(shared_dict_loc)
        sharing_string_sign = "BoTT"+"_sharing_"+"Bob"+"_"+"Joan"+"_signature"
        shared_dict_sign_loc = c.generate_memloc(sharing_key, sharing_string_sign)

        # adversary attempt to decrypt will fail, as it is asymmetrically encrypted and signed
        self.assertRaises(ValueError, lambda: c.asym_verify_dec(
            opp.priv_key, keyserver.Get("Bob_verify_key"), 
            dataserver.Get(shared_dict_sign_loc), enc_shared_dict))
        
        # if the adversary adds a phony dictionary, it will be realized as an integrity error
        u1.upload_file("NewMorn", b"Just")
        u1.share_file("NewMorn", "Joan")

        sharing_string = "NewMorn"+"_sharing_"+"Bob"+"_"+"Joan"
        sharing_key = crypto.Hash(sharing_string.encode("utf-8"))[:16]
        shared_dict_loc = c.generate_memloc(sharing_key, sharing_string)
        enc_shared_dict = dataserver.Get(shared_dict_loc)
        sharing_string_sign = "NewMorn"+"_sharing_"+"Bob"+"_"+"Joan"+"_signature"
        shared_dict_sign_loc = c.generate_memloc(sharing_key, sharing_string_sign)

        phony_shared_dict, phony_shared_signature = c.asym_enc_sign(
            keyserver.Get("Joan_pub_key"), 
            opp.sign_key,
            util.ObjectToBytes({"NewMorn": b"signature"})
        )
        
        dataserver.Set(shared_dict_loc, phony_shared_dict)
        dataserver.Set(shared_dict_sign_loc, phony_shared_signature)

        # when Joan tries receive, an error occurs
        self.assertRaises(util.DropboxError, lambda: u2.receive_file("NewMorn", "Bob")) 
        

# Start the REPL if this file is launched as the main program
if __name__ == '__main__':
    util.start_repl(locals())

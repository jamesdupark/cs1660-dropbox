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


# Start the REPL if this file is launched as the main program
if __name__ == '__main__':
    util.start_repl(locals())

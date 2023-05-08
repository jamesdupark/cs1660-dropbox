##
## test_client.py - Test for your client
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
#import dropbox_client_reference as c


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

        u1.upload_file("shared_file", b'shared data')
        u1.share_file("shared_file", "usr2")

        u2.receive_file("shared_file", "usr1")
        down_data = u2.download_file("shared_file")

        self.assertEqual(down_data, b'shared data')

        u1.revoke_file("shared_file", "usr2")
        self.assertRaises(util.DropboxError, lambda: u2.download_file("shared_file"))

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
        self.assertRaises(util.DropboxError, lambda: c.create_user("John", "yoko_ono"))

        # Users may choose the same password:
        user_2 = c.create_user("Paul", "yoko")
        user_3 = c.create_user("George", "yoko")

    def test_authenticate_user(self):
        """
        Tests to ensure authenticate_user meets conditions as specified on wiki,
        as well as some basic attacks.
        """

        # Authentication only works if both UN and PW is known
        c.create_user("Ringo", "drums")
        self.assertRaises(util.DropboxError, lambda: c.authenticate_user("John", "rhythm_guitar"))
        self.assertRaises(util.DropboxError, lambda: c.authenticate_user("Paul", "bass"))
        self.assertRaises(util.DropboxError, lambda: c.authenticate_user("Ringo", "bass"))
        self.assertRaises(util.DropboxError, lambda: c.authenticate_user("Ringo", "rhythm_guitar"))
        self.assertRaises(util.DropboxError, lambda: c.authenticate_user("Paul", "drums"))
        self.assertRaises(util.DropboxError, lambda: c.authenticate_user("John", "drums"))
        c.authenticate_user("Ringo", "drums")

        # Adversary wipes the Dataserver after a user is created
        c.create_user("John", "rhythm_guitar")
        dataserver.Clear()
        self.assertRaises(util.DropboxError, lambda: c.authenticate_user("John", "rhythm_guitar"))

        # Adversary deletes an entry on the Dataserver after a user is created
        c.create_user("Paul", "bass")
        dataserver.Delete(list(dataserver.GetMap())[0])
        self.assertRaises(util.DropboxError, lambda: c.authenticate_user("Paul", "bass"))

        # Adversary edits an value on the Dataserver after a user is created
        dataserver.Clear()
        c.create_user("George", "lead_guitar")
        dataserver.Set(list(dataserver.GetMap())[0], crypto.SecureRandom(16))
        self.assertRaises(util.DropboxError, lambda: c.authenticate_user("George", "lead_guitar"))
        
        # Adversary swaps encrypted keys between two users in Dataserver
        dataserver.Clear()
        c.create_user("George_M", "studio")
        g_priv_key = dataserver.Get(list(dataserver.GetMap())[0]) 
        g_sign_key = dataserver.Get(list(dataserver.GetMap())[1]) 
        c.create_user("Billy", "keyboard")
        b_priv_key = dataserver.Get(list(dataserver.GetMap())[2]) 
        b_sign_key = dataserver.Get(list(dataserver.GetMap())[3]) 

        dataserver.Set(list(dataserver.GetMap())[0], b_priv_key)
        dataserver.Set(list(dataserver.GetMap())[1], b_sign_key)
        self.assertRaises(util.DropboxError, lambda: c.authenticate_user("George_M", "studio"))
        dataserver.Set(list(dataserver.GetMap())[2], g_priv_key)
        dataserver.Set(list(dataserver.GetMap())[3], g_sign_key)
        self.assertRaises(util.DropboxError, lambda: c.authenticate_user("Billy", "keyboard"))

        # Adversary swaps encrypted keys between the same user
        dataserver.Clear()
        c.create_user("Mal", "anvil")
        m_priv_key = dataserver.Get(list(dataserver.GetMap())[0])
        m_sign_key = dataserver.Get(list(dataserver.GetMap())[1])
        dataserver.Set(list(dataserver.GetMap())[0], m_sign_key)
        dataserver.Set(list(dataserver.GetMap())[1], m_priv_key)
        self.assertRaises(util.DropboxError, lambda: c.authenticate_user("Mal", "anvil"))


    def test_the_next_test(self):
        """
        Implement more tests by defining more functions like this one!

        Functions have to start with the word "test" to be recognized. Refer to
        the Python `unittest` API for more information on how to write test
        cases: https://docs.python.org/3/library/unittest.html
        """
        self.assertTrue(True)


# Start the REPL if this file is launched as the main program
if __name__ == '__main__':
    util.start_repl(locals())

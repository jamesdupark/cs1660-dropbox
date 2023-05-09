##
## test_functionality.py - Some functionality tests for Dropbox
##


import unittest
import string

import support.crypto as crypto
import support.util as util

from support.dataserver import dataserver, memloc
from support.keyserver import keyserver


from client import create_user, authenticate_user, User

# Swap this with the previous line to test with the reference client
#from dropbox_client_reference import create_user, authenticate_user, User


class ClientTests(unittest.TestCase):
    def setUp(self):
        """
        This function is automatically called before every test is run. It
        clears the dataserver and keyserver to a clean state for each test case.
        """
        dataserver.Clear()
        keyserver.Clear()

    def test_create_user(self):
        """Checks user creation."""
        u = create_user("usr", "pswd")
        u2 = authenticate_user("usr", "pswd")

        self.assertEqual(vars(u), vars(u2))

    def test_upload(self):
        """Tests if uploading a file throws any errors."""
        u = create_user("usr", "pswd")
        u.upload_file("file1", b'testing data')

    def test_download(self):
        """Tests if a downloaded file has the correct data in it."""
        u = create_user("usr", "pswd")

        data_to_be_uploaded = b'testing data'

        u.upload_file("file1", data_to_be_uploaded)
        downloaded_data = u.download_file("file1")

        self.assertEqual(downloaded_data, data_to_be_uploaded)

    def test_share_and_download(self):
        """Simple test of sharing and downloading a shared file."""
        u1 = create_user("usr1", "pswd")
        u2 = create_user("usr2", "pswd")

        u1.upload_file("shared_file", b'shared data')
        u1.share_file("shared_file", "usr2")

        u2.receive_file("shared_file", "usr1")
        down_data = u2.download_file("shared_file")

        self.assertEqual(down_data, b'shared data')

    def test_download_error(self):
        """Simple test that tests that downloading a file that doesn't exist raises an error."""
        u = create_user("usr", "pswd")

        # NOTE: When using `assertRaises`, the code that is expected to raise an
        #       error needs to be passed to `assertRaises` as a lambda function.
        self.assertRaises(util.DropboxError, lambda: u.download_file("file1"))

    def test_upload_empty_string_file_data(self):
        """Tests that a empty string file data can be uploaded."""
        u = create_user("usr", "pswd")
        u.upload_file("file", b"")

    def test_upload_same_file(self):
        """Tests if uploading a file with the same name across two different users throws any errors."""
        u = create_user("usr", "pswd")
        u.upload_file("file1", b'testing data')
        u.upload_file("file1", b'testing data 2')

        u2 = create_user("usr2", "pswd")
        u2.upload_file("file1", b'testing data')
        u2.upload_file("file1", b'testing data 2')

    def test_upload_overwrites_file(self):
        """Tests overwriting an existing file."""
        u = create_user("usr", "pswd")
        u.upload_file("file1", b'testing data')
        self.assertEqual(u.download_file('file1'), b'testing data')
        u.upload_file("file1", b'testing data 2')
        self.assertEqual(u.download_file('file1'), b'testing data 2')

class TestUserCreation(unittest.TestCase):
    """
    This class tests the functionality of user creation and authentication
    """
    def setUp(self):
        """
        This function is automatically called before every test is run. It
        clears the dataserver and keyserver to a clean state for each test case.
        """
        dataserver.Clear()
        keyserver.Clear()

    def test_bad_password(self):
        """Checks password authentication."""
        create_user("usr", "pswd")
        self.assertRaises(util.DropboxError, lambda: authenticate_user("usr", "BAD"))

    def test_already_exists(self):
        """Checks that an error is raised in create_user when a user already exists."""
        create_user("usr", "pswd")
        self.assertRaises(util.DropboxError, lambda: create_user("usr", "sdfsdf"))

    def test_bad_username(self):
        """Checks nonexistent username."""
        create_user("usr", "pswd")
        self.assertRaises(util.DropboxError, lambda: authenticate_user("rsu", "pswd"))


class TestFileFunctionality(unittest.TestCase):
    def setUp(self):
        """
        This function is automatically called before every test is run. It
        clears the dataserver and keyserver to a clean state for each test case.
        """
        dataserver.Clear()
        keyserver.Clear()

    def test_upload(self):
        """Tests if uploading a file creates a new entry on the dataserver."""
        create_user("usr", "pswd")
        u = authenticate_user("usr", "pswd")

        first_keys = list(dataserver.data.keys())
        u.upload_file("file1", b'testing data')
        second_keys = list(dataserver.data.keys())

        self.assertGreater(len(second_keys), len(first_keys))

    def test_download(self):
        """Tests if a downloaded file has the correct data in it."""
        create_user("usr", "pswd")
        u = authenticate_user("usr", "pswd")

        data_to_be_uploaded = b'testing data'

        u.upload_file("file1", data_to_be_uploaded)
        downloaded_data = u.download_file("file1")

        self.assertEqual(downloaded_data, data_to_be_uploaded)

    def test_append_correctness(self):
        """Tests append_file correctness."""
        create_user("usr", "pswd")
        u = authenticate_user("usr", "pswd")
        u.upload_file("newfile", b'start data')
        u.append_file("newfile", b' appended data')
        down_data = u.download_file("newfile")
        self.assertEqual(down_data, b'start data appended data')

    def test_append_error(self):
        """Tests that an error is raised when appending bytes to file that does not exist."""
        u = create_user("usr", "pswd")
        self.assertRaises(util.DropboxError, lambda: u.append_file("f", b'123'))

    def test_overwrite(self):
        """Tests if a file can be overwritten."""
        create_user("usr", "pswd")
        u = authenticate_user("usr", "pswd")

        old_data_to_be_uploaded = b'testing data'
        new_data_to_be_uploaded = b'new data!'

        u.upload_file("file1", old_data_to_be_uploaded)
        old_downloaded_data = u.download_file("file1")
        u.upload_file("file1", new_data_to_be_uploaded)
        new_downloaded_data = u.download_file("file1")

        self.assertEqual(new_downloaded_data, new_data_to_be_uploaded)
        self.assertEqual(old_downloaded_data, old_data_to_be_uploaded)

    def test_multiple_user_instances(self):
        """Tests for stateless operation of User object by using a file from two separate instances of the same User"""
        u1 = create_user("usr", "pswd")
        u2 = authenticate_user("usr", "pswd")

        u1.upload_file("f", b'hello')

        self.assertEqual(b'hello', u2.download_file("f"))

    def test_multiple_instances_of_same_user_append_file(self):
        """Tests that multiple instances of the same user work on Dropbox in an append_file sequence."""
        u1 = create_user("user", "pwd")
        u2 = authenticate_user("user", "pwd")
        u3 = authenticate_user("user", "pwd")

        u1.upload_file("filename", b"my file data")
        u2.append_file("filename", b" plus new stuff")
        u3.append_file("filename", b" and more stuff")

        self.assertEqual(b"my file data plus new stuff and more stuff", u1.download_file("filename"))

        u2.append_file("filename", b" plus new stuff")
        u3.upload_file("filename", b"overwritten")

        self.assertEqual(b"overwritten", u1.download_file("filename"))
        self.assertEqual(b"overwritten", u2.download_file("filename"))
        self.assertEqual(b"overwritten", u3.download_file("filename"))

    def test_append_different_users_same_file(self):
        """Tests that appending to different files of the same name owned by different users works without collisions."""
        u = create_user("usr", "pswd")
        u2 = create_user("usr2", "pswd")

        u.upload_file("f", b'123')
        u.append_file("f", b'456')
        u.append_file("f", b'7890')

        u2.upload_file("f", b'abc')
        u2.append_file("f", b'def')
        u2.append_file("f", b'ghij')

        self.assertEqual(u.download_file("f"), b'1234567890')
        self.assertEqual(u2.download_file("f"), b'abcdefghij')

class TestSharingFunctionality(unittest.TestCase):
    """
    This class tests the functionality of the sharing implementation
    """

    def setUp(self):
        """
        This function is automatically called before every test is run. It
        clears the dataserver and keyserver to a clean state for each test case.
        """
        dataserver.Clear()
        keyserver.Clear()

    def test_share_and_download(self):
        """Simple test of sharing and downloading a shared file."""

        create_user("usr1", "pswd")
        u1 = authenticate_user("usr1", "pswd")

        create_user("usr2", "pswd")
        u2 = authenticate_user("usr2", "pswd")

        u1.upload_file("shared_file", b'shared data')
        u1.share_file("shared_file", "usr2")

        u2.receive_file("shared_file", "usr1")
        down_data = u2.download_file("shared_file")

        self.assertEqual(down_data, b'shared data')

    def test_multi_share_and_download(self):
        """Tests sharing and downloading a file with many users."""

        NUM_SHAREES = 15

        create_user("usr0", "pswd")
        u0 = authenticate_user("usr0", "pswd")
        u0.upload_file("shared_file", b'shared data')

        sharees = []
        for i in range(1, NUM_SHAREES + 1):
            create_user(f"usr{i}", "pswd")
            u = authenticate_user(f"usr{i}", "pswd")
            sharees.append(u)
            u0.share_file("shared_file", f"usr{i}")

            # check immediately
            u.receive_file("shared_file", "usr0")
            down_data = u.download_file("shared_file")

            self.assertEqual(down_data, b'shared data')


        # now check after all shares completed
        for u in sharees:
            down_data = u.download_file("shared_file")
            self.assertEqual(down_data, b'shared data')

    def test_revoke(self):
        """Tests simple revocation logic."""
        create_user("usr0", "pswd")
        u0 = authenticate_user("usr0", "pswd")
        u0.upload_file("shared_file", b'shared data')

        create_user("usr1", "pswd")
        u1 = authenticate_user("usr1", "pswd")

        u0.share_file("shared_file", "usr1")

        u1.receive_file("shared_file", "usr0")
        u1.download_file("shared_file")

        u0.revoke_file("shared_file", "usr1")
        u0.upload_file("shared_file", b'new shared data')

        try:
            self.assertNotEqual(b'new shared data', u1.download_file("shared_file"))
        except util.DropboxError:
            pass

    def test_error_if_not_received_shared_file(self):
        """Tests that an error is raised if recipient did not accept file."""
        u1 = create_user("usr1", "pswd")
        u2 = create_user("usr2", "pswd")

        u1.upload_file("shared_file", b'shared data')
        u1.share_file("shared_file", "usr2")

        try:
            self.assertEqual(u2.download_file("shared_file"), b'shared data')
        except util.DropboxError:
            pass

        u2.receive_file("shared_file", "usr1")
        self.assertEqual(u2.download_file("shared_file"), b'shared data')

    def test_revoke_upload(self):
        """Tests whether a revoked user can upload to a previously-shared file."""
        u1 = create_user("usr1", "pswd")
        u2 = create_user("usr2", "pswd")

        u1.upload_file("f", b'shared data')
        u1.share_file('f', 'usr2')
        u2.receive_file('f', 'usr1')

        self.assertEqual(u1.download_file("f"), b'shared data')
        self.assertEqual(u2.download_file("f"), b'shared data')

        u1.revoke_file('f', 'usr2')
        try:
            u2.upload_file('f', b'replaced data')
            self.assertEqual(u1.download_file("f"), b'shared data')
        except (util.DropboxError, ValueError):
            pass

    def test_revoke_append(self):
        """Tests whether a revoked user can append to a previously-shared file."""
        u1 = create_user("usr1", "pswd")
        u2 = create_user("usr2", "pswd")

        u1.upload_file("f", b'shared data')
        u1.share_file('f', 'usr2')
        u2.receive_file('f', 'usr1')

        self.assertEqual(u1.download_file("f"), b'shared data')
        self.assertEqual(u2.download_file("f"), b'shared data')

        u1.revoke_file('f', 'usr2')
        try:
            u2.append_file('f', b' new')
            self.assertEqual(u1.download_file("f"), b'shared data')
        except (util.DropboxError, ValueError):
            pass

    def test_share_nonexistent_file(self):
        """Tests error handling of sharing a non-existent file."""
        create_user("usr0", "pswd")
        u0 = authenticate_user("usr0", "pswd")

        create_user("usr1", "pswd")
        authenticate_user("usr1", "pswd")

        self.assertRaises(util.DropboxError, lambda: u0.share_file("shared_file", "usr1"))

    def test_revoke_nonexistent_user(self):
        """Tests error handling of calling revoke_file on a file that doesn't exist, since an util.DropboxError exception should be thrown since the user does not have access to a file that doesn't exist."""
        create_user("usr0", "pswd")
        u0 = authenticate_user("usr0", "pswd")

        create_user("usr1", "pswd")
        authenticate_user("usr1", "pswd")

        self.assertRaises(util.DropboxError, lambda: u0.revoke_file("shared_file", "usr1"))


if __name__ == '__main__':
    unittest.main()

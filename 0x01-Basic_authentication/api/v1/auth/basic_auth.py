#!/usr/bin/env python3
"""Module for basic authentication
"""
from api.v1.auth.auth import Auth
import base64
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """Class that inherits from Auth class
    """
    def extract_base64_authorization_header(
                self, authorization_header: str) -> str:
        """Method for returning base64 encoding part
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header.strip("Basic ")

    def decode_base64_authorization_header(
                self, base64_authorization_header: str) -> str:
        """Method that decodes a base64 encoding
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None

        try:
            encoded_bytes = base64_authorization_header.encode('utf-8')
            decoded_string = base64.b64decode(encoded_bytes).decode('utf-8')
            return decoded_string
        except base64.binascii.Error:
            return None

    def extract_user_credentials(
                self, decoded_base64_authorization_header: str) -> (str, str):
        """Methods that returns user email and password from base64 encoding
        """
        if decoded_base64_authorization_header is None:
            return "({}, {})".format(None, None)
        if not isinstance(decoded_base64_authorization_header, str):
            return "({}, {})".format(None, None)
        if ':' not in decoded_base64_authorization_header:
            return "({}, {})".format(None, None)

        return tuple(decoded_base64_authorization_header.split(":"))

    def user_object_from_credentials(
                self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Method that returns the User instance based on email & password
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        users = User.search({"email": user_email})
        if not users:
            return None

        for user in users:
            if user.is_valid_password(user_pwd):
                return user

        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Method that overloads Auth &
           Retrieves the User instance for a request
        """
        authorization_header = self.authorization_header(request)
        base64_header = \
            self.extract_base64_authorization_header(authorization_header)
        decoded_header = self.decode_base64_authorization_header(base64_header)
        user_email, user_pwd = self.extract_user_credentials(decoded_header)
        return self.user_object_from_credentials(user_email, user_pwd)

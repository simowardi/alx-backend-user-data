#!/usr/bin/env python3
"""
Basic authentication module for the API.
"""

import re
import base64
import binascii
from typing import Tuple, TypeVar
from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """
    Implements Basic Authentication methods for the API.
    """

    def extract_base64_authorization_header(self,
                                            auth_header: str) -> str:
        """
        Extracts the Base64 part from the Authorization header if it follows
        the Basic Authentication scheme.

        Args:
            auth_header (str): The authorization header from the request.

        Returns:
            str: The Base64 encoded token, or None if invalid.
        """
        if isinstance(auth_header, str):
            pattern = r'Basic (?P<token>.+)'
            match = re.fullmatch(pattern, auth_header.strip())
            if match:
                return match.group('token')
        return None

    def decode_base64_authorization_header(self,
                                           b64_token: str) -> str:
        """
        Decodes a Base64-encoded string from the authorization header.

        Args:
            b64_token (str): The Base64 encoded token.

        Returns:
            str: The decoded string, or None if decoding fails.
        """
        if isinstance(b64_token, str):
            try:
                decoded_bytes = base64.b64decode(b64_token, validate=True)
                return decoded_bytes.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None
        return None

    def extract_user_credentials(self,
                                 decoded_token: str) -> Tuple[str, str]:
        """
        Extracts the user's email and password from the decoded Base64 string.

        Args:
            decoded_token (str): The decoded Base64 string.

        Returns:
            Tuple[str, str]: The user's email and password,
                             or (None, None) if invalid.
        """
        if isinstance(decoded_token, str):
            pattern = r'(?P<email>[^:]+):(?P<password>.+)'
            match = re.fullmatch(pattern, decoded_token.strip())
            if match:
                return match.group('email'), match.group('password')
        return None, None

    def user_object_from_credentials(self,
                                     email: str,
                                     password: str) -> TypeVar('User'):
        """
        Retrieves a User instance based on the provided email and password.

        Args:
            email (str): The user's email.
            password (str): The user's password.

        Returns:
            User: The User instance, or None if authentication fails.
        """
        if isinstance(email, str) and isinstance(password, str):
            try:
                users = User.search({'email': email})
            except Exception:
                return None
            if users and users[0].is_valid_password(password):
                return users[0]
        return None

    def current_user(self,
                     request=None) -> TypeVar('User'):
        """
        Retrieves the authenticated User instance from the request.

        Args:
            request: The Flask request object.

        Returns:
            User: The authenticated User instance, or None
                  if authentication fails.
        """
        authorization_header = self.authorization_header(request)
        base64_token = self.extract_base64_authorization_header(
            authorization_header
        )
        decoded_credentials = self.decode_base64_authorization_header(
            base64_token
        )
        email, password = self.extract_user_credentials(decoded_credentials)
        return self.user_object_from_credentials(email, password)

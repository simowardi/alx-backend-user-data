#!/usr/bin/env python3
"""
Auth class for API authentication management.
"""

from flask import request
from typing import List, TypeVar


class Auth:
    """
    Manages API authentication.
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Checks if a path requires authentication.
        """
        if path is None or not excluded_paths:
            return True
        for x in excluded_paths:
            if x.endswith('*') and path.startswith(x[:-1]):
                return False
            if path in (x, x.rstrip('/')):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Gets the Authorization header from a request.
        """
        return request.headers.get('Authorization') if request else None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user from the request.
        """
        return None

#!/usr/bin/env python3
"""Module for API authentication
"""

from flask import Flask, request
from typing import List, TypeVar


class Auth:
    """Class that manages API authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Method for authenticating a path or route
        """
        if path is None:
            return True

        if excluded_paths is None or len(excluded_paths) == 0:
            return True

        for excluded_path in excluded_paths:
            if path.rstrip('/') == excluded_path.rstrip('/'):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """Method for adding authorization header
        """
        if request is None or "Authorization" not in request.headers:
            return None
        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar('User'):
        """Method for authenticating a user
        """
        return None

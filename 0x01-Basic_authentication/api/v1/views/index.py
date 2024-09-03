#!/usr/bin/env python3
""" Module of Index views
"""
from flask import jsonify, abort
from api.v1.views import app_views


@app_views.route('/unauthorized', methods=['GET'], strict_slashes=False)
def unauthorized_access() -> str:
    """ GET /api/v1/unauthorized
    Return:
        - raise a 401 error
    """
    abort(401, description="Unauthorized")


@app_views.route('/forbidden', methods=['GET'], strict_slashes=False)
def forbidden_access() -> str:
    """ GET /api/v1/forbidden
    Return:
        - raise a 403 error
    """
    abort(403, description="Forbidden")


@app_views.route('/status', methods=['GET'], strict_slashes=False)
def api_status() -> str:
    """ GET /api/v1/status
    Return:
      - the status of the API
    """
    return jsonify({"status": "OK"})


@app_views.route('/stats/', strict_slashes=False)
def api_stats() -> str:
    """ GET /api/v1/stats
    Return:
      - the number of each object
    """
    from models.user import User
    statistics = {}
    statistics['users'] = User.count()
    return jsonify(statistics)

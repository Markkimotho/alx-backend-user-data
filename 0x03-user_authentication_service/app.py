#!/usr/bin/env python3
"""Flask application module
"""

from flask import Flask, jsonify, request, \
            make_response, abort, redirect
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=["GET"])
def welcome():
    """Index page message
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def register_user():
    """Register's new user
    """
    email = request.form.get("email")
    password = request.form.get("password")

    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login():
    """Login method based on email & password
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if not email or not password:
        abort(400, 'Invalid request')

    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        if session_id:
            response = jsonify({
                'email': email,
                'message': 'logged in'
            })
            # Set the session_id as a cookie
            response.set_cookie('session_id', session_id)
            return response
    abort(401, 'Unauthorized')


@app.route("/sessions", methods=["DELETE"])
def logout():
    """Logs out a user based on authentication by session id
    """
    session_id = request.cookies.get("session_id")

    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            AUTH.destroy_session(user.id)
            return redirect("/", code=302)

    return "Forbidden", 403


@app.route("/profile", methods=["GET"])
def profile():
    """Gets the profile of a user & current status
    """
    session_id = request.cookies.get("session_id")

    if session_id:
        user = AUTH.get_user_from_session_id(session_id)
        if user:
            return jsonify({"email": user.email}), 200

    return "Forbidden", 403


@app.route("/reset_password", methods=["POST"])
def get_reset_password_token():
    """Generates a token that enables user to reset password
    """
    email = request.form.get("email")

    try:
        token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": token}), 200
    except ValueError:
        abort(403, "Email not registered")


@app.route("/reset_password", methods=["PUT"])
def update_password():
    """Enables a user to reset the password
    """
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")

    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        abort(403, "Invalid reset token")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port="5000")

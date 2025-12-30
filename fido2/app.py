from flask import Flask, request, jsonify, session, render_template
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers import options_to_json_dict
from webauthn.helpers.exceptions import (
    InvalidRegistrationResponse,
    InvalidAuthenticationResponse,
)
from webauthn.helpers.structs import (
    RegistrationCredential,
    AuthenticationCredential,
    AttestationConveyancePreference,
    UserVerificationRequirement,
)
import json

app = Flask(__name__)
# IMPORTANT: Use a secure, long, randomly generated secret key in production
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

# --- CONFIGURATION ---
RP_ID = "localhost"  # The domain of your application (must match the frontend)
RP_NAME = "My FIDO2 App"
ORIGIN = "http://localhost:5000"  # Your app's origin URL

# Simple "database" to store user credentials (User ID -> {credentials: [Credential]...})
user_db = {}


class CredentialStore:
    """Helper to structure how we store credentials."""

    def __init__(self, id, public_key, sign_count):
        self.id = id.hex
        self.public_key = public_key.hex
        self.sign_count = sign_count


# --- REGISTRATION ENDPOINTS ---


# @app.route("/register/begin", methods=["POST"])
def register_begin():
    """Generates the FIDO2 Registration Challenge and options."""
    # data = request.json
    # print(f"data {data}")
    # username = data.get("username")
    username = "test"

    if not username:
        return jsonify({"error": "Username required"}), 400

    # 1. Create a unique user ID and store it if new
    if username not in user_db:
        user_id = username.encode()  # Simple User ID encoding
        user_db[username] = {"id": user_id, "credentials": []}
    else:
        # Prevent re-registration for simplicity, in a real app you might allow multiple keys
        return jsonify({"error": "User already exists"}), 409

    user = user_db[username]

    # 2. Generate Registration Options (Challenge)
    options = generate_registration_options(
        rp_id=RP_ID,
        rp_name=RP_NAME,
        user_id=user["id"],
        user_name=username,
        # Exclude existing credentials if the user were allowed to register multiple
        exclude_credentials=[],
        attestation=AttestationConveyancePreference.NONE,
        # user_verification=UserVerificationRequirement.PREFERRED,
    )
    # 3. Store the challenge in the session for verification later
    options_json_dict = options_to_json(options)
    # session["current_challenge"] = options_json_dict
    # session["current_username"] = username
    print(f"session {options_json_dict}")
    # return jsonify(options_json_dict)


@app.route("/register/complete", methods=["POST"])
def register_complete():
    """Verifies the FIDO2 Registration Response from the client."""
    response_data = request.json
    challenge = session.pop("current_challenge", None)
    username = session.pop("current_username", None)

    if not challenge or not username:
        return jsonify({"error": "Registration session expired or invalid"}), 400

    try:
        # 1. Verify the registration response
        verification = verify_registration_response(
            credential=RegistrationCredential.parse_obj(response_data),
            expected_challenge=bytes.fromhex(challenge),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            require_user_verification=False,  # Set to True if user verification (PIN/Biometric) is mandatory
        )

        # 2. Extract credential info and store it
        new_credential = CredentialStore(
            id=verification.credential_id,
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
        )

        user_db[username]["credentials"].append(new_credential)

        # Log the successful registration (for demonstration)
        print(
            f"User '{username}' successfully registered credential ID: {new_credential.id}"
        )
        # print(f"Current DB: {user_db}")

        return jsonify({"message": "Registration successful"}), 200

    except InvalidRegistrationResponse as e:
        print(f"Registration verification failed: {e}")
        return jsonify({"error": f"Registration failed: {e}"}), 400


# --- AUTHENTICATION ENDPOINTS ---


@app.route("/auth/begin", methods=["POST"])
def auth_begin():
    """Generates the FIDO2 Authentication Challenge and options."""
    data = request.json
    username = data.get("username")

    if not username:
        return jsonify({"error": "Username required"}), 400

    if username not in user_db:
        return jsonify({"error": "User not found"}), 404

    user = user_db[username]

    # 1. Get all credential IDs associated with the user
    allowed_credentials = [
        {"id": bytes.fromhex(c.id), "type": "public-key"} for c in user["credentials"]
    ]

    # 2. Generate Authentication Options (Challenge)
    options = generate_authentication_options(
        rp_id=RP_ID,
        allow_credentials=allowed_credentials,
        user_verification=UserVerificationRequirement.PREFERRED,
    )

    # 3. Store the challenge in the session for verification later
    session["current_challenge"] = options.challenge.hex
    session["current_username"] = username

    # 4. Return options to the client
    return jsonify(options.dict())


@app.route("/auth/complete", methods=["POST"])
def auth_complete():
    """Verifies the FIDO2 Authentication Response from the client."""
    response_data = request.json
    challenge = session.pop("current_challenge", None)
    username = session.pop("current_username", None)

    if not challenge or not username:
        return jsonify({"error": "Authentication session expired or invalid"}), 400

    user = user_db[username]

    # 1. Find the credential used by the client from the DB
    used_credential_id = response_data["id"]
    used_credential = next(
        (c for c in user["credentials"] if c.id == used_credential_id), None
    )

    if not used_credential:
        return jsonify({"error": "Unknown credential used for authentication"}), 400

    try:
        # 2. Verify the authentication response
        verification = verify_authentication_response(
            credential=AuthenticationCredential.parse_obj(response_data),
            expected_challenge=bytes.fromhex(challenge),
            expected_origin=ORIGIN,
            expected_rp_id=RP_ID,
            credential_public_key=bytes.fromhex(used_credential.public_key),
            credential_current_sign_count=used_credential.sign_count,
            require_user_verification=False,  # Set to True if UV is mandatory
        )

        # 3. Update the sign count (security measure against replay attacks)
        used_credential.sign_count = verification.new_sign_count

        print(
            f"User '{username}' successfully authenticated with credential ID: {used_credential_id}"
        )

        # 4. Success! Log the user in (e.g., set a logged_in session flag)
        session["logged_in_user"] = username

        return (
            jsonify({"message": f"Authentication successful. Welcome, {username}!"}),
            200,
        )

    except InvalidAuthenticationResponse as e:
        print(f"Authentication verification failed: {e}")
        return jsonify({"error": f"Authentication failed: {e}"}), 400


# This is the root URL route (e.g., http://127.0.0.1:5000/)
@app.route("/")
def index():
    # Flask looks for 'index.html' inside the 'templates' folder
    return render_template("index.html")


if __name__ == "__main__":
    # Flask will run on http://localhost:5000
    # app.run(debug=True)
    register_begin()

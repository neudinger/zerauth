from fastapi import FastAPI, HTTPException, Request, Body
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import base64
import secrets
import json
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("fido2_demo")

app = FastAPI()

# In-memory storage
# users = { "username": { "id": "user_handle_bytes", "credentials": [ "cred_id_str" ] } }
users = {}
# challenges = { "challenge_string": { "username": "username", "type": "register/auth" } }
challenges = {}

# Pydantic models
class RegisterBeginRequest(BaseModel):
    username: str

class RegisterCompleteRequest(BaseModel):
    id: str
    rawId: str
    response: dict
    type: str

class AuthBeginRequest(BaseModel):
    username: str

class AuthCompleteRequest(BaseModel):
    id: str
    rawId: str
    response: dict
    type: str

# Helpers
def generate_challenge():
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')

def decode_base64url(data):
    padding = '=' * (4 - (len(data) % 4))
    return base64.urlsafe_b64decode(data + padding)

@app.get("/")
async def root():
    # Helper to serve the UI for testing
    path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(path):
        with open(path, "r") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>index.html not found</h1>")

@app.post("/register/begin")
async def register_begin(data: RegisterBeginRequest):
    logger.info(f"REGISTRATION START: Received request for user '{data.username}'")
    username = data.username
    
    # Store user handle. For a new user, generate one.
    if username not in users:
        # User handle should be random bytes
        user_handle = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8').rstrip('=')
        users[username] = {"id": user_handle, "credentials": []}
        logger.info(f"Created new user '{username}' with handle: {user_handle}")
    else:
        logger.info(f"User '{username}' already exists.")
    
    challenge = generate_challenge()
    challenges[challenge] = {"username": username, "type": "register"}
    logger.info(f"Generated registration challenge: {challenge}")
    
    response_data = {
        "challenge": challenge,
        "rp": {
            "name": "FIDO2 Demo",
            "id": "localhost" 
        },
        "user": {
            "id": users[username]["id"],
            "name": username,
            "displayName": username
        },
        "pubKeyCredParams": [
            {"type": "public-key", "alg": -7}, # ES256
            {"type": "public-key", "alg": -257} # RS256
        ],
        "timeout": 60000,
        "attestation": "none"
    }
    logger.info(f"Sending registration options: {response_data}")
    return response_data

@app.post("/register/complete")
async def register_complete(data: RegisterCompleteRequest):
    logger.info("REGISTRATION COMPLETE: Received credential verification request")
    logger.info(f"Received data: {data.dict()}")
    
    # 1. Parse clientDataJSON to get challenge
    try:
        client_data_json_b64 = data.response.get('clientDataJSON')
        client_data_json_str = decode_base64url(client_data_json_b64).decode('utf-8')
        logger.info(f"Decoded clientDataJSON: {client_data_json_str}")
        client_data_obj = json.loads(client_data_json_str)
    except Exception as e:
        logger.error(f"Error parsing clientDataJSON: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid clientDataJSON: {str(e)}")

    challenge = client_data_obj.get('challenge')
    logger.info(f"Extracted challenge from clientDataJSON: {challenge}")
    
    # 2. Verify challenge
    if challenge not in challenges:
        logger.error("Challenge not found or expired")
        raise HTTPException(status_code=400, detail="Challenge not found or expired")
    
    stored_challenge_info = challenges[challenge]
    if stored_challenge_info['type'] != 'register':
        logger.error(f"Invalid challenge type. Expected 'register', got '{stored_challenge_info['type']}'")
        raise HTTPException(status_code=400, detail="Invalid challenge type")
    
    username = stored_challenge_info['username']
    logger.info(f"Challenge verified for user: {username}")
    
    # 3. Store Credential ID
    # In a real implementation coverage, we would parse attestationObject (CBOR) to get the Public Key and store it.
    # We would also verify the signature over the challenge.
    # Without external libraries, we assume the credential is valid if the browser sent it and the challenge matches.
    
    credential_id = data.id # This is the base64url encoded credential ID
    logger.info(f"Registering credential ID: {credential_id}")
    
    if credential_id not in users[username]["credentials"]:
        users[username]["credentials"].append(credential_id)
        logger.info("Credential stored successfully.")
    else:
        logger.info("Credential already exists for user.")
    
    # Cleanup challenge
    del challenges[challenge]
    
    return {"status": "ok", "message": f"Successfully registered user {username}"}

@app.post("/auth/begin")
async def auth_begin(data: AuthBeginRequest):
    logger.info(f"AUTHENTICATION START: Received request for user '{data.username}'")
    username = data.username
    if username not in users or not users[username]["credentials"]:
        logger.warning(f"User '{username}' not found or no credentials.")
        raise HTTPException(status_code=404, detail="User not found or no credentials")
    
    challenge = generate_challenge()
    challenges[challenge] = {"username": username, "type": "auth"}
    logger.info(f"Generated authentication challenge: {challenge}")
    
    # List allowed credentials
    allow_credentials = []
    for cred_id in users[username]["credentials"]:
        allow_credentials.append({
            "id": cred_id,
            "type": "public-key",
            "transports": ["internal", "usb", "nfc"]
        })
    
    response_data = {
        "challenge": challenge,
        "allowCredentials": allow_credentials,
        "timeout": 60000,
        "userVerification": "preferred"
    }
    logger.info(f"Sending authentication options: {response_data}")
    return response_data

@app.post("/auth/complete")
async def auth_complete(data: AuthCompleteRequest):
    logger.info("AUTHENTICATION COMPLETE: Received assertion verification request")
    logger.info(f"Received data: {data.dict()}")
    
    # 1. Parse clientDataJSON
    try:
        client_data_json_b64 = data.response.get('clientDataJSON')
        client_data_json_str = decode_base64url(client_data_json_b64).decode('utf-8')
        logger.info(f"Decoded clientDataJSON: {client_data_json_str}")
        client_data_obj = json.loads(client_data_json_str)
    except Exception as e:
        logger.error(f"Error parsing clientDataJSON: {e}")
        raise HTTPException(status_code=400, detail="Invalid clientDataJSON")

    challenge = client_data_obj.get('challenge')
    logger.info(f"Extracted challenge from clientDataJSON: {challenge}")
    
    # 2. Verify challenge
    if challenge not in challenges:
        logger.error("Challenge not found")
        raise HTTPException(status_code=400, detail="Challenge not found")
        
    stored_challenge_info = challenges[challenge]
    if stored_challenge_info['type'] != 'auth':
        logger.error(f"Invalid challenge type. Expected 'auth', got '{stored_challenge_info['type']}'")
        raise HTTPException(status_code=400, detail="Invalid challenge type")

    username = stored_challenge_info['username']
    logger.info(f"Challenge verified for user: {username}")
    
    # 3. Verify that the credential ID is associated with the user
    if data.id not in users[username]["credentials"]:
        logger.error(f"Credential ID {data.id} not found in user credentials: {users[username]['credentials']}")
        raise HTTPException(status_code=400, detail="Credential not found for this user")

    # 4. (Skipped) Verify signature using stored public key.
    
    del challenges[challenge]
    logger.info("Authentication successful.")
    
    return {"status": "ok", "message": f"Authentication successful for {username}!"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

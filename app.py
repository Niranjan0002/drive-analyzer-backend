import os
import json
import io
from flask import Flask, redirect, request, session, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload
from google.auth.transport.requests import Request, AuthorizedSession

# Load .env variables
load_dotenv()

# Flask setup
app = Flask(__name__)
app.secret_key = 'your_very_secret_key_here'  # Change this in production

# ✅ Allow cross-site cookies for Render deployment
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True
)

CORS(app, supports_credentials=True)

# OAuth2 config
CLIENT_SECRET_FILE = os.getenv("CLIENT_SECRET_FILE", "client_secret.json")
SCOPES = os.getenv("SCOPES").split()
REDIRECT_URI = os.getenv("REDIRECT_URI", "http://localhost:5000/oauth2callback")

@app.route("/")
def home():
    return "✅ Drive Analyzer Flask Backend Running!"

@app.route("/login")
def login():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    auth_url, _ = flow.authorization_url(prompt='consent', access_type='offline', include_granted_scopes='true')
    return redirect(auth_url)

@app.route("/oauth2callback")
def oauth2callback():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRET_FILE,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    flow.fetch_token(authorization_response=request.url)

    creds = flow.credentials
    session['credentials'] = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'token_uri': creds.token_uri,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }
    return redirect("http://localhost:3000")

@app.route("/files")
def list_files():
    if 'credentials' not in session:
        return redirect("/login")

    creds = Credentials(**session['credentials'])
    drive_service = build('drive', 'v3', credentials=creds)

    results = drive_service.files().list(
        pageSize=100,
        fields="files(id, name, mimeType, modifiedTime, size, parents)"
    ).execute()

    return jsonify(results.get('files', []))

@app.route("/shared")
def get_shared_files():
    if 'credentials' not in session:
        return redirect("/login")

    creds = Credentials(**session['credentials'])
    drive_service = build('drive', 'v3', credentials=creds)

    try:
        results = drive_service.files().list(
            q="sharedWithMe = true",
            fields="files(id, name, mimeType, modifiedTime, size, parents)"
        ).execute()
        return jsonify(results.get('files', []))
    except Exception as e:
        print("❌ Error fetching shared files:", e)
        return jsonify([])

@app.route("/favorites")
def get_starred_files():
    if 'credentials' not in session:
        return redirect("/login")

    creds = Credentials(**session['credentials'])
    drive_service = build('drive', 'v3', credentials=creds)

    results = drive_service.files().list(
        q="starred = true and trashed = false",
        fields="files(id, name, mimeType, modifiedTime, size, parents, starred)"
    ).execute()

    return jsonify(results.get('files', []))

@app.route("/star/<file_id>", methods=['POST'])
def toggle_star(file_id):
    if 'credentials' not in session:
        return jsonify({ "status": "unauthorized" }), 401

    creds = Credentials(**session['credentials'])
    drive_service = build('drive', 'v3', credentials=creds)

    starred_status = request.json.get("starred", False)

    try:
        drive_service.files().update(
            fileId=file_id,
            body={ "starred": starred_status }
        ).execute()
        return jsonify({ "status": "success", "starred": starred_status })
    except Exception as e:
        print("❌ Error toggling star:", e)
        return jsonify({ "status": "error", "message": str(e) }), 500

@app.route("/all-files")
def list_all_files():
    if 'credentials' not in session:
        return redirect("/login")

    creds = Credentials(**session['credentials'])
    drive_service = build('drive', 'v3', credentials=creds)

    all_files = []
    page_token = None

    while True:
        response = drive_service.files().list(
            q="trashed = false",
            fields="nextPageToken, files(id, name, mimeType, modifiedTime, size, parents)",
            pageToken=page_token
        ).execute()

        all_files.extend(response.get('files', []))
        page_token = response.get('nextPageToken')
        if not page_token:
            break

    return jsonify(all_files)

@app.route("/reset")
def reset_session():
    session.clear()
    return "🔁 Session cleared. Now go to /login again."

@app.route("/folder/<folder_id>")
def get_files_in_folder(folder_id):
    if 'credentials' not in session:
        return redirect("/login")

    creds = Credentials(**session['credentials'])
    drive_service = build('drive', 'v3', credentials=creds)

    results = drive_service.files().list(
        q=f"'{folder_id}' in parents and trashed=false",
        fields="files(id, name, mimeType, modifiedTime, size)"
    ).execute()

    return jsonify(results.get('files', []))

@app.route("/storage")
def storage_info():
    if 'credentials' not in session:
        return redirect("/login")

    creds = Credentials(**session['credentials'])
    drive_service = build('drive', 'v3', credentials=creds)

    about = drive_service.about().get(fields="storageQuota").execute()
    return jsonify(about['storageQuota'])

@app.route("/user")
def get_user():
    print("🧠 Accessing /user route")

    if 'credentials' not in session:
        print("⚠️ No credentials in session")
        return 'Unauthorized', 401

    creds_data = session['credentials']
    creds = Credentials(
        token=creds_data['token'],
        refresh_token=creds_data.get('refresh_token'),
        token_uri=creds_data['token_uri'],
        client_id=creds_data['client_id'],
        client_secret=creds_data['client_secret'],
        scopes=creds_data['scopes']
    )

    if creds.expired and creds.refresh_token:
        print("🔄 Token expired — refreshing...")
        creds.refresh(Request())
        session['credentials'] = {
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'token_uri': creds.token_uri,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': creds.scopes
        }

    try:
        authed_session = AuthorizedSession(creds)
        response = authed_session.get('https://www.googleapis.com/oauth2/v2/userinfo')
        user_info = response.json()
        print("🙋 User info fetched:", user_info)

        return jsonify({
            'email': user_info.get('email'),
            'name': user_info.get('name'),
            'picture': user_info.get('picture')
        })

    except Exception as e:
        print("❌ Error accessing Google API:", e)
        return 'Unauthorized', 401

@app.route("/delete/<file_id>", methods=["DELETE"])
def delete_file(file_id):
    if 'credentials' not in session:
        return 'Unauthorized', 401

    creds = Credentials(**session['credentials'])
    drive_service = build('drive', 'v3', credentials=creds)

    try:
        drive_service.files().delete(fileId=file_id).execute()
        return jsonify({"status": "success"})
    except Exception as e:
        print("❌ Error deleting file:", e)
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/upload", methods=["POST"])
def upload_file():
    if 'credentials' not in session:
        return jsonify({'error': 'User not authenticated'}), 401

    creds = Credentials(**session['credentials'])
    drive_service = build('drive', 'v3', credentials=creds)

    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    uploaded_file = request.files['file']
    if uploaded_file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    try:
        media = MediaIoBaseUpload(io.BytesIO(uploaded_file.read()), mimetype=uploaded_file.mimetype)
        file_metadata = {'name': uploaded_file.filename, 'parents': ['root']}
        created_file = drive_service.files().create(
            body=file_metadata,
            media_body=media,
            fields='id'
        ).execute()
        return jsonify({'status': 'success', 'fileId': created_file.get('id')}), 200
    except Exception as e:
        print(f"Upload error: {e}")
        return jsonify({'error': 'Failed to upload file'}), 500

@app.route("/logout")
def logout():
    session.clear()
    return redirect("http://localhost:3000/login")

if __name__ == "__main__":
    app.run(debug=True)

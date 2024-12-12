import base64
import glob
import logging
import os
from typing import Optional, Tuple

from config import load_config
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from services import all_unique_connections, load_json_file, process_json_data

# Set up logging
logger = logging.getLogger(__name__)

# Load configurations
config = load_config()

CONFIG_DIR = config["CONFIG_DIR"]
USE_BASIC_AUTH = config["SSO"].lower() == "true"


# FastAPI app
app = FastAPI()

# Set up Jinja2 templates
templates = Jinja2Templates(directory="templates")

# Mount static files (CSS/JS/Images)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize Basic Authentication
security = HTTPBasic()


def authenticate_user(
    credentials: HTTPBasicCredentials = Depends(security),
) -> Tuple[str, str]:
    """
    FastAPI dependency for BASIC authentication.

    Args:
        credentials (HTTPBasicCredentials): Credentials provided by the client.

    Returns:
        Tuple[str, str]: The username and password.
    """
    return credentials.username, credentials.password


def check_auth(request: Request) -> Tuple[Optional[str], Optional[str]]:
    """
    Checks if BASIC authentication is required and validates credentials.

    Args:
        request (Request): The incoming request.

    Returns:
        Tuple[Optional[str], Optional[str]]: The username and password if authenticated.

    Raises:
        HTTPException: If authentication fails.
    """
    if USE_BASIC_AUTH:
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Basic "):
            raise HTTPException(
                status_code=401,
                detail="Unauthorized",
                headers={"WWW-Authenticate": "Basic"},
            )
        try:
            encoded_credentials = auth_header.split(" ")[1]
            decoded_credentials = base64.b64decode(encoded_credentials).decode("utf-8")
            username, password = decoded_credentials.split(":", 1)
        except Exception:
            raise HTTPException(
                status_code=401,
                detail="Invalid Authorization header format",
                headers={"WWW-Authenticate": "Basic"},
            )
        return username, password
    return None, None


@app.get("/{filename}.json")
async def get_file_by_name(filename: str, request: Request):
    """
    Endpoint to retrieve a specific JSON file by filename.

    Args:
        filename (str): The name of the JSON file (without extension).
        request (Request): The incoming HTTP request.

    Returns:
        dict or RedirectResponse: Processed JSON data or a redirect.
    """
    username, password = check_auth(request)  # Enforce authentication if required

    json_file = os.path.join(CONFIG_DIR, f"{filename}.json")
    if not os.path.exists(json_file):
        logger.error(f"File {filename}.json not found.")
        raise HTTPException(status_code=404, detail=f"File {filename}.json not found.")

    logger.info(f"Processing JSON file: {json_file}")
    json_data = load_json_file(json_file)
    return process_json_data(json_data, request, username, password)


@app.get("/combined")
async def get_all_configs(request: Request):
    """
    Endpoint to retrieve all unique configurations from JSON files.

    Args:
        request (Request): The incoming HTTP request.

    Returns:
        dict or RedirectResponse: Processed JSON data or a redirect.
    """
    username, password = check_auth(request)  # Enforce authentication if required
    json_data = all_unique_connections(CONFIG_DIR)
    return process_json_data(json_data, request, username, password)


@app.get("/basic-verification")
async def test_basic_auth(request: Request):
    """
    Endpoint to test BASIC authentication.

    Args:
        request (Request): The incoming HTTP request.

    Returns:
        dict: A success message if authentication succeeds.
    """
    if USE_BASIC_AUTH:
        username, password = check_auth(request)  # Enforce authentication
        return {"message": "Authenticated successfully!"}
    else:
        return {"message": "Basic Authentication is not enabled"}


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """
    Renders the main page.

    Args:
        request (Request): The incoming HTTP request.

    Returns:
        TemplateResponse: The rendered HTML page.
    """
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/api/json-files", response_class=JSONResponse)
async def get_json_files():
    """
    API endpoint to retrieve the list of JSON files.

    Returns:
        dict: A list of JSON filenames (without extensions).
    """
    json_files = glob.glob(os.path.join(CONFIG_DIR, "*.json"))
    json_files.sort()  # Sort files alphabetically
    return {
        "files": [os.path.splitext(os.path.basename(file))[0] for file in json_files]
    }

import glob
import logging
import os
import warnings

from fastapi import Depends, FastAPI
from fastapi.requests import Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from services import (
    JSON_CONFIG_DIR,
    USE_BASIC_AUTH,
    all_unique_connections,
    authenticate_user,
    load_json_file,
    process_json_data,
)
from urllib3.exceptions import InsecureRequestWarning

# Remove TLS warning messages
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Loggers can now use the global filter
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI()

# Set up Jinja2 templates
templates = Jinja2Templates(directory="templates")

# Mount static files (CSS/JS/Images)
app.mount("/static", StaticFiles(directory="static"), name="static")


# Route for specific JSON file
@app.get("/{filename}.json")
async def get_file_by_name(
    filename: str,
    request: Request,
    credentials: tuple = Depends(authenticate_user) if USE_BASIC_AUTH else None,
):
    json_file = os.path.join(JSON_CONFIG_DIR, f"{filename}.json")
    if not os.path.exists(json_file):
        logger.error(f"File {filename}.json not in directory.")
        return {"error": f"File {filename}.json not found."}

    logger.info(f"Processing JSON file: {json_file}")

    # Load the JSON data from file
    json_data = load_json_file(json_file)

    return process_json_data(json_data, request, credentials)


# This gives you access to all specified 'connections' in any json file
@app.get("/combined")
async def get_all_configs(
    request: Request,
    credentials: tuple = Depends(authenticate_user) if USE_BASIC_AUTH else None,
):
    # Load the JSON data from all files
    json_data = all_unique_connections(JSON_CONFIG_DIR)

    return process_json_data(json_data, request, credentials)


@app.get("/basic")
def test_basic_auth(
    credentials: tuple = Depends(authenticate_user) if USE_BASIC_AUTH else None,
):
    if USE_BASIC_AUTH:
        username, password = credentials
        return {
            "message": f"Welcome, {username}!",
            "username": username,
            # "password": password,
        }
    else:
        return {"message": "Basic Authentication is not enabled"}


# GET request handler for '/' to list all JSON files
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """
    Renders the main page.
    """
    return templates.TemplateResponse(
        "index.html",
        {"request": request},
    )


# Use API whenever possible
@app.get("/api/json-files", response_class=JSONResponse)
async def get_json_files():
    """
    API endpoint to retrieve the list of JSON files.
    """
    json_files = glob.glob(os.path.join(JSON_CONFIG_DIR, "*.json"))
    json_files.sort()  # Sorting files alphabetically
    # Remove .json extension for display purposes
    return {
        "files": [os.path.splitext(os.path.basename(file))[0] for file in json_files]
    }

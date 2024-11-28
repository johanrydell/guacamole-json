import glob
import logging
import os
import warnings

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse
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
async def list_json_files():
    json_files = glob.glob(os.path.join(JSON_CONFIG_DIR, "*.json"))
    json_files.sort()  # Sorting the files alphabetically

    # Check if there are JSON files available
    if not json_files:
        html_content = """
            <h1>No Configuration Files Found</h1>
            <p>No JSON configuration files were found in the directory.</p>
            <p>Please refer to the
            <a href="https://guacamole.apache.org/doc/gug/json-auth.html"
            target="_blank"> Guacamole JSON Authentication documentation </a>
            for details on setting up JSON configuration files.</p>
        """
    else:
        # Create an HTML page listing all .json files with clickable links
        html_content = "<h1>Configuration Files</h1><ul>"
        for json_file in json_files:
            file_name = os.path.basename(json_file)
            file_name_without_extension = os.path.splitext(file_name)[0]
            # Create a link to view each JSON file
            html_content += (
                f'<li><a href="/{file_name}">{file_name_without_extension}</a></li>'
            )
        html_content += "</ul>"
        html_content += "<h2>You can ONLY use one at a time.</h2>"
        html_content += '<p>Access to <a href="/combined">all</a> configurations...'

    return HTMLResponse(content=html_content)

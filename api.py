# Import necessary libraries for making HTTP requests, handling JSON, logging, and loading environment variables.
import json
import logging
import requests
from dotenv import load_dotenv
import os

# Load environment variables from a .env file in the project directory.
load_dotenv()
# Retrieve Prisma Cloud credentials and configuration from environment variables.
access_key = os.environ.get("PRISMA_CLOUD_ACCESS_KEY")
secret = os.environ.get("PRISMA_CLOUD_SECRET")
region = os.environ.get("TENANT_REGION")
path_to_console = os.environ.get("PATH_TO_CONSOLE")

# Define base headers for API requests.
base_headers = {
    "Accept": "application/json; charset=UTF-8",
}
# Define headers for POST requests, extending the base headers.
post_headers = {
    **base_headers,
    "Content-Type": "application/json; charset=UTF-8",
}
# Define the API version for the Compute Console.
console_version = "v33.03"

# Define a custom exception for when an API response is not valid JSON.
class NoProperResponseError(Exception):
    def __init__(self, original_exception, response):
        self.response = response
        self.original_exception = original_exception
        super().__init__(self.original_exception)

# Function to make a GET request to the main Prisma Cloud API.
def compose_get_request(token, url_complement, params='', region=region):
    url = f"https://{region}.prismacloud.io/{url_complement}"
    headers = {
        **base_headers,
        "x-redlock-auth": token
    }
    response = requests.request('GET', url, headers=headers, params=params)
    try:
        response_as_json = json.loads(response.content)
    except json.JSONDecodeError as error:
        raise NoProperResponseError(error, response)
    return response_as_json

# Function to make a POST or PUT request to the main Prisma Cloud API.
def compose_post_or_put_request(token, url_complement, payload='', region=region, post_over_put=True):
    url = f"https://{region}.prismacloud.io/{url_complement}"
    headers = {
        "Content-Type": "application/json; charset=UTF-8",
        "x-redlock-auth": token
    }
    response = requests.request('POST' if post_over_put else 'PUT', url, headers=headers, data=payload)
    try:
        return json.loads(response.content)
    except json.JSONDecodeError:
        return response.__dict__

# Function to make a DELETE or PATCH request to the main Prisma Cloud API.
def compose_delete_or_patch_request(token, url_complement, payload='', region=region, delete_over_patch=True):
    url = f"https://{region}.prismacloud.io/{url_complement}"
    headers = {"x-redlock-auth": token}
    response = requests.request("DELETE" if delete_over_patch else "PATCH", url, headers=headers, data=payload)
    return response

# Function to authenticate with the main Prisma Cloud API and get a session token.
def get_token(region=region, access_key=access_key, secret=secret):
    url = f"https://{region}.prismacloud.io/login"
    payload = {
        "username": access_key,
        "password": secret
    }
    payload = json.dumps(payload)
    try:
        response = requests.request("POST", url, headers=post_headers, data=payload)
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError):
        logging.error("Request /login timeout / connection error!")
        exit(1)

    response = json.loads(response.content)
    try:
        return response['token']
    except KeyError:
        logging.error(f"The token can't be accessed: {response}!")

# Function to extend the lifetime of an existing session token.
def extend_token(token):
    return compose_get_request(
        token,
        url_complement="auth_token/extend",
    )

# Function to make a POST or PUT request to the Prisma Cloud Compute Console API.
def compose_console_post_or_put_request(console_token, url_complement, payload='', path_to_console=path_to_console, params='', version=console_version, post_over_put=True):
    url = f"{path_to_console}/api/{version}/{url_complement}"
    headers = {"Authorization": f"Bearer {console_token}", "Content-Type": "application/json; charset=UTF-8"}
    response = requests.request('POST' if post_over_put else 'PUT', url, headers=headers, data=payload, params=params)
    return response

# Function to make a GET request to the Prisma Cloud Compute Console API.
def compose_console_get_request(console_token, url_complement, path_to_console=path_to_console, params='', version=console_version):
    url = f"{path_to_console}/api/{version}/{url_complement}"
    headers = {"Authorization": f"Bearer {console_token}",}
    response = requests.request('GET', url, headers=headers, params=params)
    return response

# Function to authenticate with the Prisma Cloud Compute Console API and get a token.
def get_console_token(token=None, path_to_console=path_to_console, access_key=access_key, secret=secret, version=console_version):
    url = f"{path_to_console}/api/{version}/authenticate"
    payload = json.dumps({
        "password": secret,
        "token": token,
        "username": access_key,
    })
    response = requests.request("POST", url, headers=post_headers, data=payload)
    response = json.loads(response.content)
    return response['token']
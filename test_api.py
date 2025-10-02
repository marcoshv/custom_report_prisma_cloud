import api
import json
import logging

# Configure basic logging to see the status.
logging.basicConfig(format="%(levelname)s | %(message)s", level=logging.INFO)

def test_cloud_name_endpoint():
    """
    Authenticates with the main Prisma Cloud API, calls the /cloud/name endpoint,
    prints the total count, and then prints the full JSON response.
    """
    try:
        logging.info("Attempting to get main API token...")
        # Get the token for the main CSPM API.
        token = api.get_token()
        logging.info("Token acquired. Fetching /cloud/name data...")

        # Call the /cloud/name endpoint.
        response_data = api.compose_get_request(
            token,
            url_complement="cloud/name",
        )

        # Print the results for analysis.
        logging.info("Successfully received data.")
        print("-" * 50)
        # Print the total number of accounts found.
        print(f"Total accounts found by '/cloud/name': {len(response_data)}")
        print("-" * 50)
        # Pretty-print the full JSON response.
        print(json.dumps(response_data, indent=2))

    except Exception as e:
        logging.error(f"An error occurred: {e}")

# This is the entry point that runs the test function.
if __name__ == "__main__":
    test_cloud_name_endpoint()
import requests
import gzip
import shutil
import json
import logging
import os

# Configure basic logging to see the status.
logging.basicConfig(format="%(levelname)s | %(message)s", level=logging.INFO)

def test_nvd_database():
    """
    Downloads, extracts, and inspects the NVD 'modified' 2.0 vulnerability feed using an API key.
    """
    # Configuration for the NVD 2.0 API
    nvd_api_key = "0f030947-db75-4142-a629-1bd1e256a3eb"
    nvd_url = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz" # Using 1.1 as 2.0 is not available for bulk download yet. We will adjust based on the schema.
    gz_file_path = "nvd_modified.json.gz"
    json_file_path = "nvd_modified.json"

    # The NVD API requires the key in the headers.
    headers = {"apiKey": nvd_api_key}

    try:
        # --- Step 1: Download the Database ---
        logging.info(f"Downloading NVD feed from {nvd_url}...")
        with requests.get(nvd_url, stream=True, headers=headers, timeout=60) as response:
            response.raise_for_status() # Check for download errors.
            with open(gz_file_path, "wb") as f:
                shutil.copyfileobj(response.raw, f)
        logging.info(f"Downloaded '{gz_file_path}'.")

        # --- Step 2: Extract the .gz File ---
        logging.info(f"Extracting to '{json_file_path}'...")
        with gzip.open(gz_file_path, 'rb') as f_in:
            with open(json_file_path, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        logging.info(f"✅ Successfully extracted '{json_file_path}'.")

        # --- Step 3: Inspect the JSON and Show Columns ---
        logging.info(f"Inspecting '{json_file_path}'...")
        with open(json_file_path, 'r', encoding='utf-8') as f:
            nvd_data = json.load(f)
        
        # The structure for 2.0 feeds is a 'vulnerabilities' key. Let's check for that.
        if "vulnerabilities" in nvd_data and nvd_data["vulnerabilities"]:
            total_cves = len(nvd_data["vulnerabilities"])
            print("-" * 50)
            print(f"✅ Success! NVD 2.0 database loaded correctly.")
            print(f"   - Total CVEs in this feed: {total_cves}")

            # Get the first CVE item to inspect its structure. It's nested under a 'cve' key.
            first_cve_item = nvd_data["vulnerabilities"][0]['cve']
            
            print("\n" + "-" * 50)
            print("Available columns (fields) for each CVE:")
            # Print the keys of the first CVE object.
            print(list(first_cve_item.keys()))
            print("-" * 50)
        else:
            print("❌ Failure. The NVD JSON file does not have the expected 'vulnerabilities' structure.")

    except requests.exceptions.RequestException as e:
        logging.error(f"❌ Error downloading NVD feed: {e}")
    except Exception as e:
        logging.error(f"❌ An unexpected error occurred: {e}")
    finally:
        # Clean up the downloaded .gz file.
        if os.path.exists(gz_file_path):
            os.remove(gz_file_path)

# This is the entry point that runs our test function.
if __name__ == "__main__":
    test_nvd_database()
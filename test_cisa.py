import logging
import dataclasses
import json
from cisa_kev.client import Client

# Configure basic logging to see the status.
logging.basicConfig(format="%(levelname)s | %(message)s", level=logging.INFO)

def test_cisa_catalog():
    """
    Initializes the CISA KEV Client, tests catalog download, and saves the
    full catalog to a JSON file.
    """
    try:
        logging.info("Initializing CISA KEV Client...")
        
        cisa_client = Client()
        catalog = cisa_client.get_catalog()

        print("-" * 50)
        
        if catalog and catalog.vulnerabilities:
            print(f"✅ Success! The CISA KEV catalog was loaded correctly.")
            print(f"   - Total Vulnerabilities Found: {len(catalog.vulnerabilities)}")

            first_vulnerability = catalog.vulnerabilities[0]
            vuln_dict = dataclasses.asdict(first_vulnerability)
            
            print("\n" + "-" * 50)
            print("Field names (columns) available for each vulnerability:")
            print(list(vuln_dict.keys()))
            print("-" * 50)

            # --- THIS BLOCK IS CHANGED TO SAVE TO A FILE ---
            try:
                file_name = "full_catalog.json"
                logging.info(f"Saving full catalog to '{file_name}'...")
                
                # Convert the list of Vulnerability objects to a list of dictionaries.
                catalog_as_dict_list = [dataclasses.asdict(v) for v in catalog.vulnerabilities]
                
                # Use a 'with' command to open a file and save the JSON data.
                with open(file_name, "w") as f:
                    # We use default=str to handle date objects correctly.
                    json.dump(catalog_as_dict_list, f, indent=2, default=str)
                
                logging.info(f"Successfully saved catalog to '{file_name}'.")

            except Exception as e:
                logging.error(f"Failed to save file: {e}")
            # ----------------------------------------------------

        else:
            print("❌ Failure. The CISA KEV catalog could not be loaded.")

    except Exception as e:
        logging.error(f"An error occurred during the test: {e}")

if __name__ == "__main__":
    test_cisa_catalog()
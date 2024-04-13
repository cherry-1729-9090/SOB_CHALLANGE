# import json
from functions import serialize_p2pkh,double_hash,verify_files

import os
import json

def convert_bool(value):
    if isinstance(value, str):
        # Convert string representation of boolean to Python boolean
        if value.lower() == "true":
            return True
        elif value.lower() == "false":
            return False
    # Return non-string values as is
    return value


# Define the directory containing the JSON files
directory = 'code-challenge-2024-cherry-1729-9090/mempool'

# Iterate over all files in the directory
for filename in os.listdir(directory):
    # Construct the full path to the file
    filepath = os.path.join(directory, filename)
    
    # Check if the file is a regular file
    if os.path.isfile(filepath):
        # Load the JSON file with custom boolean conversion
        with open(filepath, 'r') as file:
            data = json.load(file, object_hook=lambda d: {k: convert_bool(v) for k, v in d.items()})
        
        # Now you can work with the data dictionary, where boolean values are Python boolean values
        # For example, you can print the filename and the contents of the data dictionary
        print("File:", filename)
        print("Data:", data)
        print()

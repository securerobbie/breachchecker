import hashlib
import requests

def check_password_strength(password):
    """
    Check if the password has been exposed in a data breach using the Have I Been Pwned API.
    """
    # Convert the password to SHA-1 hash
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # Only use the first 5 characters of the hash to make the request
    hash_prefix = sha1_hash[:5]
    hash_suffix = sha1_hash[5:]

    # Make the request to the Have I Been Pwned API
    url = f"https://api.pwnedpasswords.com/range/{hash_prefix}"

    # Send the GET request to the Have I Been Pwned API
    response = requests.get(url)

    if response.status_code == 200:
        # Check if the hash suffix is in the response text (which contains the matching suffixes)
        if hash_suffix in response.text:
            print(f"WARNING: The password has been exposed {response.text.count(hash_suffix)} times.")
        else:
            print("This password has not been exposed in any known breaches.")
    else:
        print("Error: Could not check the password with the API. Status code:", response.status_code)

# Example of how to call the function
password = input("Enter password to check: ")
check_password_strength(password)

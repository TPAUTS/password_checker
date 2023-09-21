import requests
import hashlib

# this script reads passwords from a .txt file and checks the pwned api for password breaches


# api request
def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:  # response 200 = unauthorized, 400 = authorized
        raise RuntimeError(f"Error fetching {res.status_code}, check api and try again.")
    return res


# displays amount of times the password has been breached
def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(":") for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


# converts given password, splits it in two parts, checks api and returns response
def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


# reads password from .txt file, line for line and combines all steps above
def main():
    # path to .txt file
    path = ""
    try:
        with open(path, "r") as file:
            for password in file:
                count = pwned_api_check(password)
                if count:
                    print(f"{password} was found {count} times.")
                else:
                    print(f"{password} not found.")

    except FileNotFoundError as err:
        print("Wrong file path.")

    print("Done.")


if __name__ == "__main__":
    main()

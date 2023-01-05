import sys
import requests
import getopt
import json
import urllib.parse
from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
import time
import xml.etree.ElementTree as ET  # for parsing XML

from veracode_api_signing.credentials import get_credentials

class NoExactMatchFoundException(Exception):
    message=""
    def __init__(self, message_to_set):
        self.message = message_to_set

    def get_message(self):
        return self.message

json_headers = {
    "User-Agent": "Sandbox Promoter - Python Script",
    "Content-Type": "application/json"
}

xml_headers = {
    "User-Agent": "Sandbox Promoter - Python Script",
    "Content-Type": "application/xml"
}

def print_help():
    """Prints command line options and exits"""
    print("""py promote-sandbox.py -a <application_name> -s <sandbox_name> [-d]"
        Looks for a sandbox named <sandbox_name> in the application named <application_name> and promotes its latest scan
""")
    sys.exit()

def url_encode(value_to_encode):
    return urllib.parse.quote(value_to_encode, safe='')

def find_exact_match(list, to_find, outer_field_name, field_name):
    for index in range(len(list)):
        element = list[index]
        if not outer_field_name or outer_field_name in element:
            inner_element = element[outer_field_name] if outer_field_name else element
            if field_name in inner_element:
                if inner_element[field_name] == to_find:
                    return element
    print(f"Unable to find a member of list with {field_name} equal to {to_find}")
    raise NoExactMatchFoundException(f"Unable to find a member of list with {field_name} equal to {to_find}")

def url_encode_with_plus(a_string):
    return urllib.parse.quote_plus(a_string, safe='').replace("&", "%26")

def get_error_node_value(body):
    inner_node = ET.XML(body)
    if inner_node.tag == "error" and not inner_node == None:
        return inner_node.text
    else:
        return ""

def get_application_guid(api_base, application_name, verbose):
    path = f"{api_base}appsec/v1/applications?name={url_encode(application_name)}"
    if verbose:
        print(f"Calling: {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=json_headers)
    data = response.json()

    if response.status_code == 200:
        if verbose:
            print(data)
        if "_embedded" in data and len(data["_embedded"]["applications"]) > 0:
            return find_exact_match(data["_embedded"]["applications"], application_name, "profile", "name")["guid"]
        else:
            print(f"ERROR: No application named '{application_name}' found")
            return f"ERROR: No application named '{application_name}' found"
    print(f"ERROR: trying to get application named {application_name}")
    print(f"ERROR: code: {response.status_code}")
    print(f"ERROR: value: {data}")
    sys.exit(1)

def get_sandbox_guid(api_base, application_guid, sandbox_name, verbose):
    path = f"{api_base}appsec/v1/applications/{application_guid}/sandboxes"
    if verbose:
        print(f"Calling: {path}")

    response = requests.get(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=json_headers)
    data = response.json()

    if response.status_code == 200:
        if verbose:
            print(data)
        if "_embedded" in data and len(data["_embedded"]["sandboxes"]) > 0:
            return find_exact_match(data["_embedded"]["sandboxes"], sandbox_name, "", "name")["guid"]
        else:
            print(f"ERROR: No sandbox named '{sandbox_name}' found in application {application_guid}")
            sys.exit(1)
    print(f"ERROR: trying to get sandbox named {sandbox_name} in application {application_guid}")
    print(f"ERROR: code: {response.status_code}")
    print(f"ERROR: value: {data}")
    sys.exit(1)

def promote_sandbox(api_base, application_name, sandbox_name, verbose):
    application_guid=get_application_guid(api_base, application_name, verbose)
    if not application_guid:
        sys.exit(1)
    sandbox_guid=get_sandbox_guid(api_base, application_guid, sandbox_name, verbose)
    if not sandbox_guid:
        sys.exit(1)

    path = f"{api_base}appsec/v1/applications/{application_guid}/sandboxes/{sandbox_guid}/promote"
    if verbose:
        print(path)

    response = requests.post(path, auth=RequestsAuthPluginVeracodeHMAC(), headers=json_headers)

    if verbose:
        print(f"status code {response.status_code}")
        body = response.json()
        if body:
            print(body)
    if response.status_code == 200:
        print("Successfully promoted sandbox scan.")
        if verbose:
            body = response.json()
            if body:
                print(body)
    else:
        body = response.json()
        if (body):
            return f"Unable to create application profile: {response.status_code} - {body}"
        else:
            return f"Unable to create application profile: {response.status_code}"

def get_api_base():
    api_key_id, api_key_secret = get_credentials()
    api_base = "https://api.veracode.{instance}/"
    if api_key_id.startswith("vera01"):
        return api_base.replace("{instance}", "eu", 1)
    else:
        return api_base.replace("{instance}", "com", 1)

def main(argv):
    """Promotes a sandbox scan"""
    global failed_attempts
    global last_column
    excel_file = None
    try:
        verbose = False
        file_name = ''
        header_row = -1

        opts, args = getopt.getopt(argv, "hds:a:", ["sandbox_name=", "application_name="])
        for opt, arg in opts:
            if opt == '-h':
                print_help()
            if opt == '-d':
                verbose = True
            if opt in ('-s', '--sandbox_name'):
                sandbox_name=arg
            if opt in ('-a', '--application_name'):
                application_name=arg

        api_base = get_api_base()
        if application_name and sandbox_name:
            promote_sandbox(api_base, application_name, sandbox_name, verbose)
        else:
            print_help()
    except requests.RequestException as e:
        print("An error occurred!")
        print(e)
        sys.exit(1)
    finally:
        if excel_file:
            excel_file.save(filename=file_name)


if __name__ == "__main__":
    main(sys.argv[1:])

"""
Automated OS Install Tool for Cisco Intersight, v1.3
Author: Ugo Emekauwa
Contact: uemekauw@cisco.com, uemekauwa@gmail.com
Summary: The Automated OS Install Tool for Cisco Intersight automates the
         installation of operating systems on UCS servers managed by Intersight.
GitHub Repository: https://github.com/ugo-emekauwa/intersight-os-installer
"""


import sys
import traceback
import json
import copy
import intersight
import re
import urllib3
import time
import pathlib
import requests

########################
# MODULE REQUIREMENT 1 #
########################
"""
For the following variable below named key_id, please fill in between
the quotes your Intersight API Key ID.

Here is an example:
key_id = "5c89885075646127773ec143/5c82fc477577712d3088eb2f/5c8987b17577712d302eaaff"

"""
key_id = ""


########################
# MODULE REQUIREMENT 2 #
########################
"""
For the following variable below named key, please fill in between
the quotes your system's file path to your Intersight API key "SecretKey.txt"
file.

Here is an example:
key = "C:\\Users\\demouser\\Documents\\SecretKey.txt"

"""
key = ""


########################
# MODULE REQUIREMENT 3 #
########################
"""
Provide the required configuration settings to automate 
OS installations on Cisco Intersight. Remove the sample
values and replace them with your own, where applicable.
"""

####### Start Configuration Settings - Provide values for the variables listed below. #######

# General Settings
## NOTE - For the "Server Identifier" key below, the accepted values are the Server serial, name, model, PID (product ID), or user label. This information can be found in Intersight, if needed.
## If there are Server with duplicate names, models, PIDs, or user labels, please use the serial to ensure the correct Server is selected.
## Here is an example using the Server serial: "Server Identifier": " FCH37527777"
## Here is an example using the Server name: "Server Identifier": "UCS-IMM-Pod-1-1"
## Here is an example using the Server model: "Server Identifier": "UCSX-210C-M7"
## Here is an example using the Server PID: "Server Identifier": "UCSX-210C-M7"
## For the "Server Form Factor" key, the options are "Blade or "Rack".
## For the "Server Connection Type" key, the options are "FI-Attached" or "Standalone".
## To install an OS on additional target servers, add more dictionary entries below.
os_install_target_server_id_dictionary = {
    "Server Identifier": "UCS-IMM-Pod-1-1",
    "Server Form Factor": "Blade",
    "Server Connection Type": "FI-Attached"
    }
os_install_organization = "default"
os_install_tags = {"Org": "IT", "Dept": "DevOps"}  # Empty the os_install_tags dictionary if no tags are needed, for example: os_install_tags = {}

# Operating System Settings
## Add OS Image Link
os_image_link_access_protocol_type = "NFS"       # Options: "CIFS", "NFS", "HTTP/S"
os_image_link_file_location = "192.168.1.25/isos/ubuntu-22.04.4-live-server-amd64.iso"
os_image_link_mount_options = ""
os_image_link_access_username = ""
os_image_link_access_password = ""
os_image_link_name = "Ubuntu Server 22.04.2 ISO Image - 001"
os_image_link_vendor = "Ubuntu"      # Options: "CentOS", "Citrix", "Microsoft", "Nutanix", "Oracle", "Red Hat", "Rocky Linux, "SuSE", "Ubuntu", "VMware" as of 6/4/24. See Intersight docs for updates.
os_image_link_version = "Ubuntu Server 22.04.2 LTS"      # Options: "CentOS 8.3", "Windows Server 2022", "Rocky Linux 9.1", "Ubuntu Server 22.04.2 LTS", "ESXi 8.0 U2", "ESXi 7.0 U3", Etc. See Intersight docs for all available options.
os_image_link_description = "OS Image Link added by the Automated OS Install Tool for Cisco Intersight."

## Select Pre-Loaded OS Image Link (Change only if using an OS Image Link that has already been loaded into the target Intersight account)
pre_loaded_os_image_link = False
pre_loaded_os_image_link_name = ""

## Microsoft Windows Server OS Specific Settings (Only applicable if installing Microsoft Windows Server)
os_install_windows_server_edition = ""      # Options: "Standard", "Datacenter", "StandardCore", "DatacenterCore". Provide an empty string ("") if installing other OSs.

# Configuration Settings (Only "File" (Custom File from Local Machine) and "Embedded" configuration sources are supported at this time)
os_install_configuration_file_source = "File"     # Options: "File", "Embedded"

## Custom File - Local Machine Configuration Source (Only applicable if os_install_configuration_file_source is set to "File")
os_install_configuration_file_location = "C:\\Users\\demouser\\Documents\\OS Configuration Files\\ubuntu-cloud-config-host1-v1.cfg"
os_install_configuration_file_location_type = "local"       # Options: "local", "http"
os_install_remove_return_from_configuration_file = True     # NOTE: Change only if there are issues reading the configuration file.

# Server Configuration Utility Settings
## Add SCU Image Link
scu_image_link_access_protocol_type = "NFS"       # Options: "CIFS", "NFS", "HTTP/S"
scu_image_link_file_location = "192.168.1.25/isos/ucs-scu-6.3.2c.iso"
scu_image_link_mount_options = ""
scu_image_link_access_username = ""
scu_image_link_access_password = ""
scu_image_link_name = "UCS SCU 6.3(2c) ISO Image - 001"
scu_image_link_version = "6.3(2c)"      # Options: "CentOS 8.3", "Windows Server 2022", "Rocky Linux 9.1", "Ubuntu Server 22.04.2 LTS", "ESXi 8.0 U2", etc. See Intersight docs for all available options.
scu_image_link_supported_models = ["UCSX-210C-M6", "UCSX-210C-M7", "UCSB-B200-M5"]
scu_image_link_description = "SCU Image Link added by the Automated OS Install Tool for Cisco Intersight."

## Select Pre-Loaded SCU Image Link (Change only if using a SCU Image Link that has already been loaded into the target Intersight account)
pre_loaded_scu_image_link = False
pre_loaded_scu_image_link_name = ""

# Installation Target Disk Storage Settings (Only "Local Disk" connectivity is supported at this time, Fibre Channel and iSCSI will be added when tested.)
os_install_target_disk_type = "Virtual"     # Options: "Virtual", "Physical"
os_install_target_disk_name = "MStorBootVd"
os_install_target_disk_storage_controller_slot = "MSTOR-RAID"       # Options: "MSTOR-RAID", "MRAID", "FMEZZ1-SAS", "NVMe-direct-U.2-drives", Etc. See Intersight docs for more options.
os_install_target_disk_virtual_id = "0"
os_install_target_disk_physical_serial_number = ""

# Secure Boot Settings
os_install_secure_boot_override = True

# Misc Settings (Change only if needed)
os_install_name = f"Sample_OS_Install_{int(time.time())}"
os_install_description = f"Sample OS Install launched at {int(time.time())}."
os_install_method = "vMedia"        # NOTE: Only "vMedia" is supported at this time by Intersight. iPXE to be supported in the future.

# Intersight Base URL Setting (Change only if using the Intersight Virtual Appliance)
intersight_base_url = "https://www.intersight.com/api/v1"
url_certificate_verification = True

####### Finish Configuration Settings - The required value entries are complete. #######


#############################################################################################################################
#############################################################################################################################


# Suppress InsecureRequestWarning error messages
urllib3.disable_warnings()

# Function to get Intersight API client as specified in the Intersight Python SDK documentation for OpenAPI 3.x
## Modified to align with overall formatting, try/except blocks added for additional error handling, certificate verification option added
def get_api_client(api_key_id,
                   api_secret_file,
                   endpoint="https://intersight.com",
                   url_certificate_verification=True
                   ):
    try:
        with open(api_secret_file, 'r') as f:
            api_key = f.read()
        
        if re.search('BEGIN RSA PRIVATE KEY', api_key):
            # API Key v2 format
            signing_algorithm = intersight.signing.ALGORITHM_RSASSA_PKCS1v15
            signing_scheme = intersight.signing.SCHEME_RSA_SHA256
            hash_algorithm = intersight.signing.HASH_SHA256

        elif re.search('BEGIN EC PRIVATE KEY', api_key):
            # API Key v3 format
            signing_algorithm = intersight.signing.ALGORITHM_ECDSA_MODE_DETERMINISTIC_RFC6979
            signing_scheme = intersight.signing.SCHEME_HS2019
            hash_algorithm = intersight.signing.HASH_SHA256

        configuration = intersight.Configuration(
            host=endpoint,
            signing_info=intersight.signing.HttpSigningConfiguration(
                key_id=api_key_id,
                private_key_path=api_secret_file,
                signing_scheme=signing_scheme,
                signing_algorithm=signing_algorithm,
                hash_algorithm=hash_algorithm,
                signed_headers=[
                    intersight.signing.HEADER_REQUEST_TARGET,
                    intersight.signing.HEADER_HOST,
                    intersight.signing.HEADER_DATE,
                    intersight.signing.HEADER_DIGEST,
                    ]
                )
            )

        if not url_certificate_verification:
            configuration.verify_ssl = False
    except Exception:
        print("\nA configuration error has occurred!\n")
        print("Unable to access the Intersight API Key.")
        print("Exiting due to the Intersight API Key being unavailable.\n")
        print("Please verify that the correct API Key ID and API Key have "
              "been entered, then re-attempt execution.\n")
        print("Exception Message: ")
        traceback.print_exc()
        sys.exit(0)
        
    return intersight.ApiClient(configuration)


# Establish function to test for the availability of the Intersight API and Intersight account
def test_intersight_api_service(intersight_api_key_id,
                                intersight_api_key,
                                intersight_base_url="https://www.intersight.com/api/v1",
                                preconfigured_api_client=None
                                ):
    """This is a function to test the availability of the Intersight API and
    Intersight account. The tested Intersight account contains the user who is
    the owner of the provided Intersight API Key and Key ID.

    Args:
        intersight_api_key_id (str):
            The ID of the Intersight API key.
        intersight_api_key (str):
            The system file path of the Intersight API key.
        intersight_base_url (str):
            Optional; The base URL for Intersight API paths. The default value
            is "https://www.intersight.com/api/v1". This value typically only
            needs to be changed if using the Intersight Virtual Appliance. The
            default value is "https://www.intersight.com/api/v1".
        preconfigured_api_client ("ApiClient"):
            Optional; An ApiClient class instance which handles
            Intersight client-server communication through the use of API keys.
            The default value is None. If a preconfigured_api_client argument
            is provided, empty strings ("") or None can be provided for the
            intersight_api_key_id, intersight_api_key, and intersight_base_url
            arguments.

    Returns:
        A string of the name for the Intersight account tested, verifying the
        Intersight API service is up and the Intersight account is accessible.
        
    Raises:
        Exception:
            An exception occurred due to an issue with the provided API Key
            and/or API Key ID.
    """
    # Define Intersight SDK ApiClient variable
    if preconfigured_api_client is None:
        api_client = get_api_client(api_key_id=intersight_api_key_id,
                                    api_secret_file=intersight_api_key,
                                    endpoint=intersight_base_url
                                    )
    else:
        api_client = preconfigured_api_client
    try:
        # Check that Intersight Account is accessible
        print("Testing access to the Intersight API by verifying the "
              "Intersight account information...")
        api_client.call_api(resource_path="/iam/Accounts",
                            method="GET",
                            auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                            )
        response = api_client.last_response.data
        iam_account = json.loads(response)
        if api_client.last_response.status != 200:
            print("\nThe Intersight API and Account Availability Test did not "
                  "pass.")
            print("The Intersight account information could not be verified.")
            print("Exiting due to the Intersight account being unavailable.\n")
            print("Please verify that the correct API Key ID and API Key have "
                  "been entered, then re-attempt execution.\n")
            sys.exit(0)
        else:
            intersight_account_name = iam_account["Results"][0]["Name"]
            print("The Intersight API and Account Availability Test has "
                  "passed.\n")
            print(f"The Intersight account named '{intersight_account_name}' "
                  "has been found.")
            return intersight_account_name
    except Exception:
        print("\nA configuration error has occurred!\n")
        print("Unable to access the Intersight API.")
        print("Exiting due to the Intersight API being unavailable.\n")
        print("Please verify that the correct API Key ID and API Key have "
              "been entered, then re-attempt execution.\n")
        print("Exception Message: ")
        traceback.print_exc()
        sys.exit(0)


# Establish function to retrieve the MOID of a specific Intersight API object by name
def intersight_object_moid_retriever(intersight_api_key_id,
                                     intersight_api_key,
                                     object_name,
                                     intersight_api_path,
                                     object_type="object",
                                     organization="default",
                                     intersight_base_url="https://www.intersight.com/api/v1",
                                     preconfigured_api_client=None
                                     ):
    """This is a function to retrieve the MOID of Intersight objects
    using the Intersight API.

    Args:
        intersight_api_key_id (str):
            The ID of the Intersight API key.
        intersight_api_key (str):
            The system file path of the Intersight API key.
        object_name (str):
            The name of the Intersight object.
        intersight_api_path (str):
            The Intersight API path of the Intersight object.
        object_type (str):
            Optional; The type of Intersight object. The default value is
            "object".
        organization (str):
            Optional; The Intersight organization of the Intersight object.
            The default value is "default".
        intersight_base_url (str):
            Optional; The base URL for Intersight API paths. The default value
            is "https://www.intersight.com/api/v1". This value typically only
            needs to be changed if using the Intersight Virtual Appliance.
        preconfigured_api_client ("ApiClient"):
            Optional; An ApiClient class instance which handles
            Intersight client-server communication through the use of API keys.
            The default value is None. If a preconfigured_api_client argument
            is provided, empty strings ("") or None can be provided for the
            intersight_api_key_id, intersight_api_key, and intersight_base_url
            arguments.

    Returns:
        A string of the MOID for the provided Intersight object.
        
    Raises:
        Exception:
            An exception occurred due to an issue accessing the Intersight API
            path. The status code or error message will be specified.
    """
    # Define Intersight SDK ApiClient variable
    if preconfigured_api_client is None:
        api_client = get_api_client(api_key_id=intersight_api_key_id,
                                    api_secret_file=intersight_api_key,
                                    endpoint=intersight_base_url
                                    )
    else:
        api_client = preconfigured_api_client
    try:
        # Retrieve the Intersight Account name
        api_client.call_api(resource_path="/iam/Accounts",
                            method="GET",
                            auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                            )
        response = api_client.last_response.data
        iam_account = json.loads(response)
        if api_client.last_response.status != 200:
            print("The provided Intersight account information could not be "
                  "accessed.")
            print("Exiting due to the Intersight account being unavailable.\n")
            print("Please verify that the correct API Key ID and API Key have "
                  "been entered, then re-attempt execution.\n")
            sys.exit(0)
        else:
            intersight_account_name = iam_account["Results"][0]["Name"]
    except Exception:
        print("\nA configuration error has occurred!\n")
        print("Unable to access the Intersight API.")
        print("Exiting due to the Intersight API being unavailable.\n")
        print("Please verify that the correct API Key ID and API Key have "
              "been entered, then re-attempt execution.\n")
        sys.exit(0)
    # Retrieving the provided object from Intersight...
    full_intersight_api_path = f"/{intersight_api_path}"
    try:
        api_client.call_api(resource_path=full_intersight_api_path,
                            method="GET",
                            auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                            )
        response = api_client.last_response.data
        intersight_objects = json.loads(response)
        # The Intersight API resource path has been accessed successfully.
    except Exception:
        print("\nA configuration error has occurred!\n")
        print("There was an issue retrieving the "
              f"{object_type} from Intersight.")
        print("Unable to access the provided Intersight API resource path "
              f"'{intersight_api_path}'.")
        print("Please review and resolve any error messages, then re-attempt "
              "execution.\n")
        print("Exception Message: ")
        traceback.print_exc()
        sys.exit(0)

    if intersight_objects.get("Results"):
        for intersight_object in intersight_objects.get("Results"):
            if intersight_object.get("Organization"):
                provided_organization_moid = intersight_object_moid_retriever(intersight_api_key_id=None,
                                                                              intersight_api_key=None,
                                                                              object_name=organization,
                                                                              intersight_api_path="organization/Organizations?$top=1000",
                                                                              object_type="Organization",
                                                                              preconfigured_api_client=api_client
                                                                              )
                if intersight_object.get("Organization", {}).get("Moid") == provided_organization_moid:
                    if intersight_object.get("Name") == object_name:
                        intersight_object_moid = intersight_object.get("Moid")
                        # The provided object and MOID has been identified and retrieved.
                        return intersight_object_moid
            else:
                if intersight_object.get("Name") == object_name:
                    intersight_object_moid = intersight_object.get("Moid")
                    # The provided object and MOID has been identified and retrieved.
                    return intersight_object_moid
        else:
            print("\nA configuration error has occurred!\n")
            print(f"The provided {object_type} named '{object_name}' was not "
                  "found.")
            print("Please check the Intersight Account named "
                  f"{intersight_account_name}.")
            print("Verify through the API or GUI that the needed "
                  f"{object_type} is present.")
            print(f"If the needed {object_type} is missing, please create it.")
            print("Once the issue has been resolved, re-attempt execution.\n")
            sys.exit(0)
    else:
        print("\nA configuration error has occurred!\n")
        print(f"The provided {object_type} named '{object_name}' was not "
              "found.")
        print(f"No requested {object_type} instance is currently available in "
              f"the Intersight account named {intersight_account_name}.")
        print("Please check the Intersight Account named "
              f"{intersight_account_name}.")
        print(f"Verify through the API or GUI that the needed {object_type} "
              "is present.")
        print(f"If the needed {object_type} is missing, please create it.")
        print("Once the issue has been resolved, re-attempt execution.\n")
        sys.exit(0)


# Establish function to retrieve all instances of a particular Intersight API object type
def get_intersight_objects(intersight_api_key_id,
                           intersight_api_key,
                           intersight_api_path,
                           object_type="object",
                           intersight_base_url="https://www.intersight.com/api/v1",
                           preconfigured_api_client=None
                           ):
    """This is a function to perform an HTTP GET on all objects under an
    available Intersight API type.

    Args:
        intersight_api_key_id (str):
            The ID of the Intersight API key.
        intersight_api_key (str):
            The system file path of the Intersight API key.
        intersight_api_path (str):
            The path to the targeted Intersight API object type. For example,
            to specify the Intersight API type for adapter configuration
            policies, enter "adapter/ConfigPolicies". More API types can be
            found in the Intersight API reference library at
            https://intersight.com/apidocs/introduction/overview/.
        object_type (str):
            Optional; The type of Intersight object. The default value is
            "object".
        intersight_base_url (str):
            Optional; The base URL for Intersight API paths. The default value
            is "https://www.intersight.com/api/v1". This value typically only
            needs to be changed if using the Intersight Virtual Appliance.
        preconfigured_api_client ("ApiClient"):
            Optional; An ApiClient class instance which handles
            Intersight client-server communication through the use of API keys.
            The default value is None. If a preconfigured_api_client argument
            is provided, empty strings ("") or None can be provided for the
            intersight_api_key_id, intersight_api_key, and intersight_base_url
            arguments.

    Returns:
        A dictionary containing all objects of the specified API type. If the
        API type is inaccessible, an implicit value of None will be returned.
        
    Raises:
        Exception:
            An exception occurred due to an issue accessing the Intersight API
            path. The status code or error message will be specified.
    """
    # Define Intersight SDK ApiClient variable
    if preconfigured_api_client is None:
        api_client = get_api_client(api_key_id=intersight_api_key_id,
                                    api_secret_file=intersight_api_key,
                                    endpoint=intersight_base_url
                                    )
    else:
        api_client = preconfigured_api_client
    # Retrieving the provided object from Intersight...
    full_intersight_api_path = f"/{intersight_api_path}"
    try:
        api_client.call_api(resource_path=full_intersight_api_path,
                            method="GET",
                            auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                            )
        response = api_client.last_response.data
        intersight_objects = json.loads(response)
        # The Intersight API resource path has been accessed successfully.
        return intersight_objects
    except Exception:
        print("\nA configuration error has occurred!\n")
        print(f"There was an issue retrieving the requested {object_type} "
              "instances from Intersight.")
        print("Unable to access the provided Intersight API resource path "
              f"'{intersight_api_path}'.")
        print("Please review and resolve any error messages, then re-attempt "
              "execution.\n")
        print("Exception Message: ")
        traceback.print_exc()
        sys.exit(0)


# Establish function to retrieve a particular instance of a particular Intersight API object type
def get_single_intersight_object(intersight_api_key_id,
                                 intersight_api_key,
                                 intersight_api_path,
                                 object_moid,
                                 object_type="object",
                                 intersight_base_url="https://www.intersight.com/api/v1",
                                 preconfigured_api_client=None
                                 ):
    """This is a function to perform an HTTP GET on a single object under an
    available Intersight API type.

    Args:
        intersight_api_key_id (str):
            The ID of the Intersight API key.
        intersight_api_key (str):
            The system file path of the Intersight API key.
        intersight_api_path (str):
            The path to the targeted Intersight API object type. For example,
            to specify the Intersight API type for adapter configuration
            policies, enter "adapter/ConfigPolicies". More API types can be
            found in the Intersight API reference library at
            https://intersight.com/apidocs/introduction/overview/.
        object_moid (str):
            The MOID of the single Intersight object.
        object_type (str):
            Optional; The type of Intersight object. The default value is
            "object".
        intersight_base_url (str):
            Optional; The base URL for Intersight API paths. The default value
            is "https://www.intersight.com/api/v1". This value typically only
            needs to be changed if using the Intersight Virtual Appliance.
        preconfigured_api_client ("ApiClient"):
            Optional; An ApiClient class instance which handles
            Intersight client-server communication through the use of API keys.
            The default value is None. If a preconfigured_api_client argument
            is provided, empty strings ("") or None can be provided for the
            intersight_api_key_id, intersight_api_key, and intersight_base_url
            arguments.

    Returns:
        A dictionary containing all objects of the specified API type. If the
        API type is inaccessible, an implicit value of None will be returned.
        
    Raises:
        Exception:
            An exception occurred due to an issue accessing the Intersight API
            path. The status code or error message will be specified.
    """
    # Define Intersight SDK ApiClient variable
    if preconfigured_api_client is None:
        api_client = get_api_client(api_key_id=intersight_api_key_id,
                                    api_secret_file=intersight_api_key,
                                    endpoint=intersight_base_url
                                    )
    else:
        api_client = preconfigured_api_client
    # Retrieving the provided object from Intersight...
    full_intersight_api_path = f"/{intersight_api_path}/{object_moid}"
    try:
        api_client.call_api(resource_path=full_intersight_api_path,
                            method="GET",
                            auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                            )
        response = api_client.last_response.data
        single_intersight_object = json.loads(response)
        # The Intersight API resource path has been accessed successfully.
        return single_intersight_object
    except Exception:
        print("\nA configuration error has occurred!\n")
        print(f"There was an issue retrieving the requested {object_type} "
              "instance from Intersight.")
        print("Unable to access the provided Intersight API resource path "
              f"'{intersight_api_path}'.")
        print("Please review and resolve any error messages, then re-attempt "
              "execution.\n")
        print("Exception Message: ")
        traceback.print_exc()
        sys.exit(0)


# Establish advanced function to retrieve Intersight API objects
def advanced_intersight_object_moid_retriever(intersight_api_key_id,
                                              intersight_api_key,
                                              object_attributes,
                                              intersight_api_path,
                                              object_type="object",
                                              organization="default",
                                              intersight_base_url="https://www.intersight.com/api/v1",
                                              preconfigured_api_client=None
                                              ):
    """This is a function to retrieve the MOID of Intersight objects based on
    various provided attributes using the Intersight API.

    Args:
        intersight_api_key_id (str):
            The ID of the Intersight API key.
        intersight_api_key (str):
            The system file path of the Intersight API key.
        object_attributes (dict):
            A dictionary containing the identifying attribute keys and values
            of the Intersight object to be found.
        intersight_api_path (str):
            The Intersight API path of the Intersight object.
        object_type (str):
            Optional; The type of Intersight object. The default value is
            "object".
        organization (str):
            Optional; The Intersight organization of the Intersight object.
            The default value is "default".
        intersight_base_url (str):
            Optional; The base URL for Intersight API paths. The default value
            is "https://www.intersight.com/api/v1". This value typically only
            needs to be changed if using the Intersight Virtual Appliance.
        preconfigured_api_client ("ApiClient"):
            Optional; An ApiClient class instance which handles
            Intersight client-server communication through the use of API keys.
            The default value is None. If a preconfigured_api_client argument
            is provided, empty strings ("") or None can be provided for the
            intersight_api_key_id, intersight_api_key, and intersight_base_url
            arguments.

    Returns:
        A string of the MOID for the provided Intersight object.
        
    Raises:
        Exception:
            An exception occurred due to an issue accessing the Intersight API
            path. The status code or error message will be specified.
    """
    # Define Intersight SDK ApiClient variable
    if preconfigured_api_client is None:
        api_client = get_api_client(api_key_id=intersight_api_key_id,
                                    api_secret_file=intersight_api_key,
                                    endpoint=intersight_base_url
                                    )
    else:
        api_client = preconfigured_api_client
    try:
        # Retrieve the Intersight Account name
        api_client.call_api(resource_path="/iam/Accounts",
                            method="GET",
                            auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                            )
        response = api_client.last_response.data
        iam_account = json.loads(response)
        if api_client.last_response.status != 200:
            print("The provided Intersight account information could not be "
                  "accessed.")
            print("Exiting due to the Intersight account being unavailable.\n")
            print("Please verify that the correct API Key ID and API Key have "
                  "been entered, then re-attempt execution.\n")
            sys.exit(0)
        else:
            intersight_account_name = iam_account["Results"][0]["Name"]
    except Exception:
        print("\nA configuration error has occurred!\n")
        print("Unable to access the Intersight API.")
        print("Exiting due to the Intersight API being unavailable.\n")
        print("Please verify that the correct API Key ID and API Key have "
              "been entered, then re-attempt execution.\n")
        sys.exit(0)
    # Retrieving the provided object from Intersight...
    full_intersight_api_path = f"/{intersight_api_path}"
    try:
        api_client.call_api(resource_path=full_intersight_api_path,
                            method="GET",
                            auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                            )
        response = api_client.last_response.data
        intersight_objects = json.loads(response)
        # The Intersight API resource path has been accessed successfully.
    except Exception:
        print("\nA configuration error has occurred!\n")
        print("There was an issue retrieving the "
              f"{object_type} from Intersight.")
        print("Unable to access the provided Intersight API resource path "
              f"'{intersight_api_path}'.")
        print("Please review and resolve any error messages, then re-attempt "
              "execution.\n")
        print("Exception Message: ")
        traceback.print_exc()
        sys.exit(0)

    if intersight_objects.get("Results"):
        for intersight_object in intersight_objects.get("Results"):
            if intersight_object.get("Organization"):
                provided_organization_moid = intersight_object_moid_retriever(intersight_api_key_id=None,
                                                                              intersight_api_key=None,
                                                                              object_name=organization,
                                                                              intersight_api_path="organization/Organizations?$top=1000",
                                                                              object_type="Organization",
                                                                              preconfigured_api_client=api_client
                                                                              )
                if intersight_object.get("Organization", {}).get("Moid") == provided_organization_moid:
                    for object_attribute in object_attributes:
                        try:
                            intersight_object[object_attribute]
                        except KeyError:
                            break
                        if intersight_object.get(object_attribute) != object_attributes.get(object_attribute):
                            break
                    else:
                        intersight_object_moid = intersight_object.get("Moid")
                        # The provided object and MOID has been identified and retrieved.
                        return intersight_object_moid
            else:
                for object_attribute in object_attributes:
                    try:
                        intersight_object[object_attribute]
                    except KeyError:
                        break
                    if intersight_object.get(object_attribute) != object_attributes.get(object_attribute):
                        break
                else:
                    intersight_object_moid = intersight_object.get("Moid")
                    # The provided object and MOID has been identified and retrieved.
                    return intersight_object_moid
        else:
            print("\nA configuration error has occurred!\n")
            print(f"The provided {object_type} was not found.")
            print("Please check the Intersight Account named "
                  f"{intersight_account_name}.")
            print("Verify through the API or GUI that the needed "
                  f"{object_type} is present.")
            print(f"If the needed {object_type} is missing, please create it.")
            print("Once the issue has been resolved, re-attempt execution.\n")
            sys.exit(0)
    else:
        print("\nA configuration error has occurred!\n")
        print(f"The provided {object_type} was not found.")
        print(f"No requested {object_type} instance is currently available in "
              f"the Intersight account named {intersight_account_name}.")
        print("Please check the Intersight Account named "
              f"{intersight_account_name}.")
        print(f"Verify through the API or GUI that the needed {object_type} "
              "is present.")
        print(f"If the needed {object_type} is missing, please create it.")
        print(f"Once the issue has been resolved, re-attempt execution.\n")
        sys.exit(0)


# Establish function to convert a list of strings in string type format to list type format.
def string_to_list_maker(string_list,
                         remove_duplicate_elements_in_list=True
                         ):
    """This function converts a list of strings in string type format to list
    type format. The provided string should contain commas, semicolons, or
    spaces as the separator between strings. For each string in the list,
    leading and rear spaces will be removed. Duplicate strings in the list are
    removed by default.

    Args:
        string_list (str):
            A string containing an element or range of elements.

        remove_duplicate_elements_in_list (bool):
            Optional; A setting to determine whether duplicate elements are
            removed from the provided string list. The default value is True.

    Returns:
        A list of elements.   
    """
    def string_to_list_separator(string_list,
                                 separator
                                 ):
        """This function converts a list of elements in string type format to
        list type format using the provided separator. For each element in the
        list, leading and rear spaces are removed.

        Args:
            string_list (str):
                A string containing an element or range of elements.

            separator (str):
                The character to identify where elements in the
                list should be separated (e.g., a comma, semicolon,
                hyphen, etc.).

        Returns:
            A list of separated elements that have been stripped of any spaces.   
        """
        fully_stripped_list = []
        # Split string by provided separator and create list of separated elements.
        split_list = string_list.split(separator)
        for element in split_list:
            if element:
                # Remove leading spaces from elements in list.
                lstripped_element = element.lstrip()
                # Remove rear spaces from elements in list.
                rstripped_element = lstripped_element.rstrip()
                # Populate new list with fully stripped elements.
                fully_stripped_list.append(rstripped_element)
        return fully_stripped_list

    def list_to_list_separator(provided_list,
                               separator
                               ):
        """This function converts a list of elements in list type format to
        list type format using the provided separator. For each element in the
        list, leading and rear spaces are removed.

        Args:
            provided_list (list): A list of elements to be separated.

            separator (str): The character to identify where elements in the
                list should be separated (e.g., a comma, semicolon,
                hyphen, etc.).

        Returns:
            A list of separated elements that have been stripped of any spaces.        
        """
        new_list = []
        # Split list by provided separator and create new list of separated elements.
        for element in provided_list:
            if separator in element:
                split_provided_list = string_to_list_separator(element, separator)
                new_list.extend(split_provided_list)
            else:
                new_list.append(element)
        return new_list
    
    staged_list = []
    # Split provided list by spaces.
    space_split_list = string_to_list_separator(string_list, " ")
    # Split provided list by commas.
    post_comma_split_list = list_to_list_separator(space_split_list, ",")
    # Split provided list by semicolons.
    post_semicolon_split_list = list_to_list_separator(post_comma_split_list, ";")
    # Split provided list by hyphens.
    for post_semicolon_split_string_set in post_semicolon_split_list:
        staged_list.append(post_semicolon_split_string_set)
    # Remove duplicates from list if enabled.
    if remove_duplicate_elements_in_list:
        final_list = list(set(staged_list))
    return final_list


# Establish function to load a configuration file
def load_configuration_file(
    configuration_file_location,
    configuration_file_location_type="local",
    remove_return_from_configuration_file=True
    ):
    """This is a function to load a file containing configuration data in
    string format.
    
    Args:
        configuration_file_location (str):
            The location of the configuration file.
        configuration_file_location_type (str):
            Optional; The location type for the configuration file. Available
            options are "local" for local file paths and "http" for access over 
            a URL. The default value is "local".
        remove_return_from_configuration_file (bool):
            Optional; The option to remove any instance of '\r' from the
            content of the configuration file. The default value is True.

    Returns:
        The configuration file data in string format.
        
    Raises:
        Exception:
            An exception was raised due to an error reading the configuration
            file.
    """
    # Load the configuration file
    try:
        if configuration_file_location_type == "local":
            configuration_file = pathlib.Path(configuration_file_location)
            configuration_file_data = configuration_file.read_text()
            if remove_return_from_configuration_file:
                return configuration_file_data.replace('\r', '')
            else:
                return configuration_file_data
        elif configuration_file_location_type == "http":
            http_configuration_file_url_response = requests.get(configuration_file_location)
            if http_configuration_file_url_response.status_code == 200:
                if remove_return_from_configuration_file:
                    return http_configuration_file_url_response.text.replace('\r', '')
                else:
                    return http_configuration_file_url_response.text
            else:
                print("\nA configuration error has occurred!\n")
                print("There was an issue reading the configuration file at "
                             "the location:")
                print(f"'{configuration_file_location}'\n")
                print("The response status code is: "
                             f"{http_configuration_file_url_response.status_code}\n")
                print("Please review and resolve any error messages, then "
                             "re-attempt execution.\n")
                sys.exit(0)
        else:
            print("\nA configuration error has occurred!\n")
            print("There was an issue with the value "
                  "provided for the configuration_file_location_type argument.")
            print(f"The value provided was {configuration_file_location_type}.")
            print("To proceed, the value provided for the "
                         "configuration_file_location_type argument should be "
                         "updated to an accepted string format.")
            print("The accepted values are 'local' or 'http'.")
            print("Please update the argument, then re-attempt "
                  "execution.\n")
            sys.exit(0)
    except Exception:
        print("\nA configuration error has occurred!\n")
        print("There was an issue reading the configuration file at the location:")
        print(f"'{configuration_file_location}'\n")
        print("Please review and resolve any error messages, then re-attempt "
              "execution.\n")
        print("Exception Message: ")
        traceback.print_exc()
        sys.exit(0)


# Establish function to retrieve target server data
def retrieve_target_server_data(
    intersight_api_key_id,
    intersight_api_key,
    server_identifier,
    server_form_factor="Blade",
    server_connection_type="FI-Attached",
    intersight_base_url="https://www.intersight.com/api/v1",
    preconfigured_api_client=None
    ):
    """
    This is a function to retrieve data for the target server of an
    Intersight OS install.

    Args:
        intersight_api_key_id (str):
            The ID of the Intersight API key.
        intersight_api_key (str):
            The system file path of the Intersight API key.
        server_identifier (str):
            The identifier of the target server for the OS install.
        server_form_factor (str):
            Optional; The form factor of the target server. The accepted values
            are "Blade" or "Rack". The default value is "Blade".
        server_connection_type (str):
            Optional; The connection type of the target server. The accepted
            values are "FI-Attached" or "Standalone". IMM (Intersight Managed
            Mode) environments should use "FI-Attached". The default value is
            "FI-Attached".
        intersight_base_url (str):
            Optional; The base URL for Intersight API paths. The default value
            is "https://www.intersight.com/api/v1". This value typically only
            needs to be changed if using the Intersight Virtual Appliance.
        preconfigured_api_client ("ApiClient"):
            Optional; An ApiClient class instance which handles
            Intersight client-server communication through the use of API keys.
            The default value is None. If a preconfigured_api_client argument
            is provided, empty strings ("") or None can be provided for the
            intersight_api_key_id, intersight_api_key, and intersight_base_url
            arguments.

    Returns:
        A dictionary with the data needed for the "Server" attribute of the
        Intersight OS Install object.
    """
    # Define Intersight SDK ApiClient variable
    if preconfigured_api_client is None:
        api_client = get_api_client(api_key_id=intersight_api_key_id,
                                    api_secret_file=intersight_api_key,
                                    endpoint=intersight_base_url
                                    )
    else:
        api_client = preconfigured_api_client
    try:
        # Retrieve the Intersight Account name
        api_client.call_api(resource_path="/iam/Accounts",
                            method="GET",
                            auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                            )
        response = api_client.last_response.data
        iam_account = json.loads(response)
        if api_client.last_response.status != 200:
            print("The provided Intersight account information could not be "
                  "accessed.")
            print("Exiting due to the Intersight account being unavailable.\n")
            print("Please verify that the correct API Key ID and API Key have "
                  "been entered, then re-attempt execution.\n")
            sys.exit(0)
        else:
            intersight_account_name = iam_account["Results"][0]["Name"]
    except Exception:
        print("\nA configuration error has occurred!\n")
        print("Unable to access the Intersight API.")
        print("Exiting due to the Intersight API being unavailable.\n")
        print("Please verify that the correct API Key ID and API Key have "
              "been entered, then re-attempt execution.\n")
        sys.exit(0)
    # If a Server Identifier has been provided, retrieve the targeted Server data
    if server_identifier:
        print("The provided server identifier for retrieval is "
              f"'{server_identifier}'.")
        provided_server_identifiers = string_to_list_maker(server_identifier)
        # Determine Server Form Factor
        if server_form_factor == "Blade":
            provided_server_form_factor = "Blades"
            provided_server_object_type = "Blade Server"
        elif server_form_factor == "Rack":
            provided_server_form_factor = "RackUnits"
            provided_server_object_type = "Rack Server"
        else:
            print("\nA configuration error has occurred!\n")
            print(f"During the retrieval of the data for the server "
                  f"identifier '{server_identifier}', there was an issue "
                  "with the value provided for the server form factor "
                  "setting.")
            print(f"The value provided was {server_form_factor}.")
            print("To proceed, the value provided for the server form "
                  "factor setting should be updated to an accepted string "
                  "format.")
            print("The accepted values are 'Blade' or 'Rack'.")
            print("Please update the configuration, then re-attempt "
                  "execution.\n")
            sys.exit(0)
        # Determine the Server Type (Target Platform or Management Mode)
        if server_connection_type == "FI-Attached":
            provided_server_connection_type = "FI-Attached"
            provided_server_management_mode = "Intersight"
        elif server_connection_type == "Standalone":
            provided_server_connection_type = "Standalone"
            provided_server_management_mode = "IntersightStandalone"
        else:
            print("\nA configuration error has occurred!\n")
            print(f"During the retrieval of the data for the server "
                  f"identifier '{server_identifier}', there was an issue "
                  "with the value provided for the server type setting.")
            print(f"The value provided was {server_connection_type}.")
            print("To proceed, the value provided for the server type "
                  "setting should be updated to an accepted string format.")
            print("The accepted values are 'FI-Attached' or 'Standalone'.")
            print("Please update the configuration, then re-attempt "
                  "execution.\n")
            sys.exit(0)
        # Find provided Server
        retrieved_intersight_servers = get_intersight_objects(
            intersight_api_key_id=None,
            intersight_api_key=None,
            intersight_api_path=f"compute/{provided_server_form_factor}?$top=1000&$filter=ManagementMode%20eq%20%27{provided_server_management_mode}%27",
            object_type=f"{provided_server_object_type}",
            preconfigured_api_client=api_client
            )
        if retrieved_intersight_servers.get("Results"):
            matching_intersight_server = None
            for intersight_server in retrieved_intersight_servers.get("Results"):
                server_serial = intersight_server.get("Serial", "")
                server_name = intersight_server.get("Name", "")
                server_model = intersight_server.get("Model", "")
                server_user_label = intersight_server.get("UserLabel", "")
                for server_identifier in provided_server_identifiers:
                    if server_identifier in [server_serial,
                                             server_name,
                                             server_model,
                                             server_user_label
                                             ]:
                        matching_intersight_server = intersight_server
                        break
                if matching_intersight_server:
                    break
            else:
                print("\nA configuration error has occurred!\n")
                print("There was an issue retrieving the server data "
                      "in Intersight.")
                print(f"A {provided_server_object_type} with the provided "
                      f"identifier of '{server_identifier}' was "
                      "not found.")
                print("Please check the Intersight Account named "
                      f"{intersight_account_name}.")
                print("Verify through the API or GUI that the needed "
                      f"{provided_server_object_type} and matching "
                      "identifier are present.")
                print("If any associated Intersight Target is missing, such as "
                      "an Intersight Managed Domain through an attached Fabric "
                      "Interconnect pair, claiming it first may be required.")
                print(f"Once the issue has been resolved, re-attempt "
                      "execution.\n")
                sys.exit(0)
        else:
            print("\nA configuration error has occurred!\n")
            print("There was an issue retrieving the server data "
                  "in Intersight.")
            print(f"The {provided_server_object_type} with the provided "
                  f"identifier of '{server_identifier}' was not "
                  "found.")
            print(f"No {provided_server_object_type}s could be found in "
                  "the Intersight account named "
                  f"{intersight_account_name}.")
            print(f"Compatible {provided_server_object_type}s need to be "
                  f"{provided_server_connection_type}.")
            print("Please check the Intersight Account named "
                  f"{intersight_account_name}.")
            print("Verify through the API or GUI that the needed "
                  f"{provided_server_object_type} and matching "
                  "identifier are present.")
            print("If any associated Intersight Target is missing, such as an "
                  "Intersight Managed Domain through an attached Fabric "
                  "Interconnect pair, claiming it first may be required.")
            print("Once the issue has been resolved, re-attempt execution.\n")
            sys.exit(0)
        # Log name of found matching Server
        matching_intersight_server_name = matching_intersight_server.get("Name")
        print(f"A matching {provided_server_object_type} named "
              f"{matching_intersight_server_name} has been found.")
        # Create the dictionary for the provided Server Identifier
        matching_intersight_server_moid = matching_intersight_server.get("Moid")
        matching_intersight_server_object_type = matching_intersight_server.get("ObjectType")
        matching_intersight_server_dictionary = {
            "ClassId": "mo.MoRef",
            "Moid": matching_intersight_server_moid,
            "ObjectType": matching_intersight_server_object_type,
            "link": f"{intersight_base_url}/compute/{provided_server_form_factor}/{matching_intersight_server_moid}"
            }
        return matching_intersight_server_dictionary           
    # Display error message if no Server Identifier is provided
    else:
        print("\nA configuration error has occurred!\n")
        print("There was an issue retrieving the server data in "
              "Intersight.")
        print("In order to retrieve the server data, a "
              "server identifier must also be provided.")
        print("Please check the value provided for the "
              "server identifier.")
        print("Once the issue has been resolved, re-attempt execution.\n")
        sys.exit(0)            
    

# Establish classes and functions to make an OS Image Link
class OsImageLink:
    """This class is used to configure an Operating System (OS) Image Link in Intersight.
    """
    object_type = "OS Image Link"
    intersight_api_path = "softwarerepository/OperatingSystemFiles"
    
    def __init__(
        self,
        intersight_api_key_id,
        intersight_api_key,
        image_link_name,
        image_link_file_location,
        image_link_mount_options="",
        image_link_access_protocol_type="CIFS",
        image_link_access_username="",
        image_link_access_password="",
        image_link_description="",
        organization="default",
        intersight_base_url="https://www.intersight.com/api/v1",
        tags=None,
        preconfigured_api_client=None,
        image_link_version="",
        image_link_vendor=""
        ):
        self.intersight_api_key_id = intersight_api_key_id
        self.intersight_api_key = intersight_api_key
        self.image_link_name = image_link_name
        self.image_link_file_location = image_link_file_location
        self.image_link_mount_options = image_link_mount_options
        self.image_link_access_protocol_type = image_link_access_protocol_type
        self.image_link_access_username = image_link_access_username
        self.image_link_access_password = image_link_access_password
        self.image_link_description = image_link_description
        self.organization = organization
        self.intersight_base_url = intersight_base_url
        if tags is None:
            self.tags = {}
        else:
            self.tags = tags
        if preconfigured_api_client is None:
            self.api_client = get_api_client(api_key_id=intersight_api_key_id,
                                             api_secret_file=intersight_api_key,
                                             endpoint=intersight_base_url
                                             )
        else:
            self.api_client = preconfigured_api_client
        self.image_link_version = image_link_version
        self.image_link_vendor = image_link_vendor
        self.intersight_api_body = {
            "Name": self.image_link_name,
            "Description": self.image_link_description,
            "Version": self.image_link_version,
            "Vendor": self.image_link_vendor,
            "Source": {}
            }

    def __repr__(self):
        return (
            f"{self.__class__.__name__}"
            f"('{self.intersight_api_key_id}', "
            f"'{self.intersight_api_key}', "
            f"'{self.image_link_name}', "
            f"'{self.image_link_file_location}', "
            f"'{self.image_link_mount_options}', "
            f"'{self.image_link_access_protocol_type}', "
            f"'{self.image_link_access_username}', "
            f"'{self.image_link_access_password}', "
            f"'{self.image_link_description}', "
            f"'{self.organization}', "
            f"'{self.intersight_base_url}', "
            f"{self.tags}, "
            f"{self.api_client}, "
            f"'{self.image_link_version}', "
            f"'{self.image_link_vendor}')"
            )

    def __str__(self):
        return f"{self.__class__.__name__} class object for '{self.image_link_name}'"

    def _post_intersight_object(self):
        """This is a function to configure an Intersight object by
        performing a POST through the Intersight API.

        Returns:
            A string with a statement indicating whether the POST method
            was successful or failed.
            
        Raises:
            Exception:
                An exception occurred while performing the API call.
                The status code or error message will be specified.
        """
        full_intersight_api_path = f"/{self.intersight_api_path}"
        try:
            self.api_client.call_api(resource_path=full_intersight_api_path,
                                     method="POST",
                                     body=self.intersight_api_body,
                                     auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                                     )
            print(f"The configuration of the base {self.object_type} "
                  "has completed.")
            return "The POST method was successful."
        except intersight.exceptions.ApiException as error:
            if error.status == 409:
                existing_intersight_object_name = self.intersight_api_body.get("Name", "object")
                print(f"The targeted {self.object_type} appears to already "
                      "exist.")
                print("An attempt will be made to update the pre-existing "
                      f"{existing_intersight_object_name}...")
                try:
                    existing_intersight_object_moid = intersight_object_moid_retriever(intersight_api_key_id=None,
                                                                                       intersight_api_key=None,
                                                                                       object_name=existing_intersight_object_name,
                                                                                       intersight_api_path=f"{self.intersight_api_path}?$top=1000",
                                                                                       object_type=self.object_type,
                                                                                       organization=self.organization,
                                                                                       preconfigured_api_client=self.api_client
                                                                                       )
                    # Update full Intersight API path with the MOID of the existing object
                    full_intersight_api_path_with_moid = f"/{self.intersight_api_path}/{existing_intersight_object_moid}"
                    self.api_client.call_api(resource_path=full_intersight_api_path_with_moid,
                                             method="POST",
                                             body=self.intersight_api_body,
                                             auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                                             )
                    print(f"The update of the {self.object_type} has "
                          "completed.")
                    print(f"The pre-existing {existing_intersight_object_name} "
                          "has been updated.")
                    return "The POST method was successful."
                except Exception:
                    print("\nA configuration error has occurred!\n")
                    print(f"Unable to update the {self.object_type} under the "
                          "Intersight API resource path "
                          f"'{full_intersight_api_path_with_moid}'.\n")
                    print(f"The pre-existing {existing_intersight_object_name} "
                          "could not be updated.")
                    print("Exception Message: ")
                    traceback.print_exc()
                    return "The POST method failed."
            else:
                print("\nA configuration error has occurred!\n")
                print(f"Unable to configure the {self.object_type} under the "
                      "Intersight API resource path "
                      f"'{full_intersight_api_path}'.\n")
                print("Exception Message: ")
                traceback.print_exc()
                return "The POST method failed."
        except Exception:
            print("\nA configuration error has occurred!\n")
            print(f"Unable to configure the {self.object_type} under the "
                  "Intersight API resource path "
                  f"'{full_intersight_api_path}'.\n")
            print("Exception Message: ")
            traceback.print_exc()
            return "The POST method failed."

    def _update_api_body_tag_attribute(self):
        """This function updates the Intersight API body with general
        attributes for the Intersight object.
        """
        # Create the Intersight Tags dictionary list
        tags_dictionary_list = []
        if self.tags:
            for key in self.tags:
                tags_dictionary_list_entry = {
                    "Key": key,
                    "Value": self.tags.get(key)
                    }
                tags_dictionary_list.append(tags_dictionary_list_entry)
        # Update the API body with the Intersight Tags dictionary list
        self.intersight_api_body["Tags"] = tags_dictionary_list

    def _update_api_body_image_link_access_protocol_type(self):
        """This function updates the Intersight API body with the Image Link Access Protocol Type
        i.e. target platform in the accepted format.
        
        Raises:
            Exception:
                An exception occurred while reformatting a provided value for
                an attribute. The issue will likely be due to the provided
                value not being in string format. Changing the value to string
                format should resolve the exception.
        """    
        # Update the API body with the provided Image Link Access Protocol Type
        # Reformat the user provided image_link_access_protocol_type variable value to lowercase and remove spaces to prevent potential format issues
        try:
            reformatted_image_link_access_protocol_type_variable_value = "".join(self.image_link_access_protocol_type.lower().split())
        except Exception:
            print("\nA configuration error has occurred!\n")
            print(f"During the configuration of the {self.object_type} named "
                  f"{self.policy_name}, there was an issue with the value "
                  "provided for the Image Link Access Protocol Type setting.")
            print(f"The value provided was {image_link_access_protocol_type}.")
            print("To proceed, the value provided for the Image Link Access "
                  "Protocol Type setting should be updated to an accepted "
                  "string format.")
            print("The accepted values are 'CIFS', 'NFS', or 'HTTP/S'.")
            print("Please update the configuration, then re-attempt "
                  "execution.\n")
            sys.exit(0)
        if reformatted_image_link_access_protocol_type_variable_value == "cifs":
            self.intersight_api_body["Source"]["ObjectType"] = "softwarerepository.CifsServer"
            self.intersight_api_body["Source"]["FileLocation"] = self.image_link_file_location
        elif reformatted_image_link_access_protocol_type_variable_value == "nfs":
            self.intersight_api_body["Source"]["ObjectType"] = "softwarerepository.NfsServer"
            self.intersight_api_body["Source"]["FileLocation"] = self.image_link_file_location
        elif reformatted_image_link_access_protocol_type_variable_value == "http/s":
            self.intersight_api_body["Source"]["ObjectType"] = "softwarerepository.HttpServer"
            self.intersight_api_body["Source"]["LocationLink"] = self.image_link_file_location
        else:
            print("\nA configuration error has occurred!\n")
            print(f"During the configuration of the {self.object_type} named "
                  f"{self.policy_name}, there was an issue with the value "
                  "provided for the Image Link Access Protocol Type setting.")
            print(f"The value provided was {image_link_access_protocol_type}.")
            print("To proceed, the value provided for the Image Link Access "
                  "Protocol Type setting should be updated to an accepted "
                  "string format.")
            print("The accepted values are 'CIFS', 'NFS', or 'HTTP/S'.")
            print("Please update the configuration, then re-attempt "
                  "execution.\n")
            sys.exit(0)

    def object_preparation(self):
        """This function makes the targeted policy object.
        """           
        print(f"\nConfiguring the {self.object_type} named "
              f"{self.image_link_name}...")
        # Update the API body with general attributes
        self._update_api_body_tag_attribute()
        # Update the API body with the Image Link Access Protocol Type
        self._update_api_body_image_link_access_protocol_type()
        # Update the API body with any provided Image Link Mount Options
        if self.image_link_mount_options:
            self.intersight_api_body["Source"]["MountOption"] = self.image_link_mount_options
        # Update the API body with any provided Image Link Access Credentials
        if self.image_link_access_username:
            self.intersight_api_body["Source"]["Username"] = self.image_link_access_username
        if self.image_link_access_password:
            self.intersight_api_body["Source"]["Password"] = self.image_link_access_password
        # Update the API body with the Image Link Catalog
        image_link_software_repository_catalog_moid = intersight_object_moid_retriever(
            intersight_api_key_id=None,
            intersight_api_key=None,
            object_name="user-catalog",
            intersight_api_path="softwarerepository/Catalogs?$top=1000",
            object_type="Software Repository Catalog",
            organization=self.organization,
            preconfigured_api_client=self.api_client
            )
        self.intersight_api_body["Catalog"] = image_link_software_repository_catalog_moid

    def object_maker(self):
        """This function makes the targeted policy object.
        """
        # Prepare the API body
        self.object_preparation()
        # POST the API body to Intersight
        self._post_intersight_object()


def add_os_image_link(
    intersight_api_key_id,
    intersight_api_key,
    image_link_name,
    image_link_file_location,
    image_link_mount_options="",
    image_link_access_protocol_type="CIFS",
    image_link_access_username="",
    image_link_access_password="",
    image_link_vendor="",
    image_link_version="",
    image_link_description="",
    organization="default",
    intersight_base_url="https://www.intersight.com/api/v1",
    tags=None,
    preconfigured_api_client=None
    ):
    """This is a function used to add an Operating System (OS) Image Link on
    Cisco Intersight.

    Args:
        intersight_api_key_id (str):
            The ID of the Intersight API key.
        intersight_api_key (str):
            The system file path of the Intersight API key.
        image_link_name (str):
            The name of the image link to be created. 
        image_link_file_location (str):
            The file location of the image. From the Intersight
            documentation: "The accepted format is
            'IP-or-hostname/folder1/folder2/.../imageFile'."
        image_link_mount_options (str):
            Optional; The mount options for the image file dependent on whether
            NFS or CIFS is the access protocol type. From the Intersight
            documentation: "For NFS, leave the field blank or enter one or more
            comma seperated options from the following. For Example, " " ,
            " ro " , " ro , rw " . * ro. * rw. * nolock. * noexec. * soft. *
            PORT=VALUE. * timeo=VALUE. * retry=VALUE. For CIFS, leave the field
            blank or enter one or more comma seperated options from the
            following. For Example, " " , " soft " , " soft , nounix " . * soft.
            * nounix. * noserviceino. * guest. * USERNAME=VALUE.
            * PASSWORD=VALUE. * sec=VALUE (VALUE could be None, Ntlm, Ntlmi,
            Ntlmssp, Ntlmsspi, Ntlmv2, Ntlmv2i)." The default value is an empty
            string ("").
        image_link_access_protocol_type (str):
            Optional; The type of protocol to be used to access the image file.
            The options are "CIFS", "NFS", and "HTTP/S". The default value is
            "CIFS".
        image_link_access_username (str):
            Optional; The username for accessing the image file location. The
            default value is an empty string ("").
        image_link_access_password (str):
            Optional; The password for accessing the image file location. The
            default value is an empty string ("").
        image_link_vendor (str):
            Optional; The vendor of the software image. Available options
            include "CentOS", "Citrix", "Microsoft", "Nutanix", "Oracle",
            "Red Hat", "Rocky Linux, "SuSE", "Ubuntu", "VMware" as of 6/4/24.
            See Intersight documentation for updates. The default value is an
            empty string ("").
        image_link_version (str):
            Optional; The version of the software image. Available options
            include "CentOS 8.3", "Windows Server 2022", "Rocky Linux 9.1",
            "Ubuntu Server 22.04.2 LTS", "ESXi 8.0 U2", etc. See the Intersight
            documentation for all the current available options. The default
            value is an empty string ("").
        image_link_description (str):
            Optional; The description of the image link to be
            created. The default value is an empty string ("").
        organization (str):
            Optional; The Intersight account organization of the image link.
            The default value is "default".
        intersight_base_url (str):
            Optional; The base URL for Intersight API paths. The default value
            is "https://www.intersight.com/api/v1". This value typically only
            needs to be changed if using the Intersight Virtual Appliance.
        tags (dict):
            Optional; The Intersight account tags that will be assigned to the
            profile template. The default value is None.
        preconfigured_api_client ("ApiClient"):
            Optional; An ApiClient class instance which handles
            Intersight client-server communication through the use of API keys.
            The default value is None. If a preconfigured_api_client argument
            is provided, empty strings ("") or None can be provided for the
            intersight_api_key_id, intersight_api_key, and intersight_base_url
            arguments.
    """
    def builder(target_object):
        """This is a function used to build the objects that are components of
        an overarching pool, policy, profile, template or related object on
        Cisco Intersight.

        Args:
            target_object (class):
                The class representing the object to be built on Intersight.

        Raises:
            Exception:
                An exception occurred due to an issue accessing the Intersight
                API path. The status code or error message will be specified.
        """
        try:
            target_object.object_maker()
        except Exception:
            print("\nA configuration error has occurred!\n")
            print("The builder function failed to configure the "
                  f"{target_object.object_type} settings.")
            print("Please check the provided arguments for the "
                  f"{target_object.object_type} settings.\n")
            print("Exception Message: ")
            traceback.print_exc()

    # Define and create OS Image Link object in Intersight
    builder(
        OsImageLink(
            intersight_api_key_id=intersight_api_key_id,
            intersight_api_key=intersight_api_key,
            image_link_name=image_link_name,
            image_link_file_location=image_link_file_location,
            image_link_mount_options=image_link_mount_options,
            image_link_access_protocol_type=image_link_access_protocol_type,
            image_link_access_username=image_link_access_username,
            image_link_access_password=image_link_access_password,
            image_link_description=image_link_description,
            organization=organization,
            intersight_base_url=intersight_base_url,
            tags=tags,
            preconfigured_api_client=preconfigured_api_client,
            image_link_version=image_link_version,
            image_link_vendor=image_link_vendor
            ))


# Establish classes and functions to make a SCU Image Link
class ScuImageLink(OsImageLink):
    """This class is used to configure a Server Configuration Utility (SCU) Image Link in Intersight.
    """
    object_type = "SCU Image Link"
    intersight_api_path = "firmware/ServerConfigurationUtilityDistributables"

    def __init__(
        self,
        intersight_api_key_id,
        intersight_api_key,
        image_link_name,
        image_link_file_location,
        image_link_mount_options="",
        image_link_access_protocol_type="CIFS",
        image_link_access_username="",
        image_link_access_password="",
        image_link_description="",
        organization="default",
        intersight_base_url="https://www.intersight.com/api/v1",
        tags=None,
        preconfigured_api_client=None,
        image_link_version="",
        image_link_vendor="Cisco",
        image_link_supported_models=None
        ):
        super().__init__(
            intersight_api_key_id,
            intersight_api_key,
            image_link_name,
            image_link_file_location,
            image_link_mount_options,
            image_link_access_protocol_type,
            image_link_access_username,
            image_link_access_password,
            image_link_description,
            organization,
            intersight_base_url,
            tags,
            preconfigured_api_client,
            image_link_version,
            image_link_vendor
            )
        if image_link_supported_models is None:
            self.image_link_supported_models = []
        else:
            self.image_link_supported_models = image_link_supported_models
        self.intersight_api_body = {
            "Name": self.image_link_name,
            "Description": self.image_link_description,
            "Version": self.image_link_version,
            "Vendor": self.image_link_vendor,
            "Source": {},
            "SupportedModels": self.image_link_supported_models
            }

    def __repr__(self):
        return (
            f"{self.__class__.__name__}"
            f"('{self.intersight_api_key_id}', "
            f"'{self.intersight_api_key}', "
            f"'{self.image_link_name}', "
            f"'{self.image_link_file_location}', "
            f"'{self.image_link_mount_options}', "
            f"'{self.image_link_access_protocol_type}', "
            f"'{self.image_link_access_username}', "
            f"'{self.image_link_access_password}', "
            f"'{self.image_link_description}', "
            f"'{self.organization}', "
            f"'{self.intersight_base_url}', "
            f"{self.tags}, "
            f"{self.api_client}, "
            f"'{self.image_link_version}', "
            f"'{self.image_link_vendor}', "
            f"{self.image_link_supported_models})"
            )


def add_scu_image_link(
    intersight_api_key_id,
    intersight_api_key,
    image_link_name,
    image_link_file_location,
    image_link_mount_options="",
    image_link_access_protocol_type="CIFS",
    image_link_access_username="",
    image_link_access_password="",
    image_link_vendor="Cisco",
    image_link_version="",
    image_link_supported_models=None,
    image_link_description="",
    organization="default",
    intersight_base_url="https://www.intersight.com/api/v1",
    tags=None,
    preconfigured_api_client=None
    ):
    """This is a function used to add an Operating System (OS) Image Link on
    Cisco Intersight.

    Args:
        intersight_api_key_id (str):
            The ID of the Intersight API key.
        intersight_api_key (str):
            The system file path of the Intersight API key.
        image_link_name (str):
            The name of the image link to be created. 
        image_link_file_location (str):
            The file location of the image. From the Intersight
            documentation: "The accepted format is
            'IP-or-hostname/folder1/folder2/.../imageFile'."
        image_link_mount_options (str):
            Optional; The mount options for the image file dependent on whether
            NFS or CIFS is the access protocol type. From the Intersight
            documentation: "For NFS, leave the field blank or enter one or more
            comma seperated options from the following. For Example, " " ,
            " ro " , " ro , rw " . * ro. * rw. * nolock. * noexec. * soft. *
            PORT=VALUE. * timeo=VALUE. * retry=VALUE. For CIFS, leave the field
            blank or enter one or more comma seperated options from the
            following. For Example, " " , " soft " , " soft , nounix " . * soft.
            * nounix. * noserviceino. * guest. * USERNAME=VALUE.
            * PASSWORD=VALUE. * sec=VALUE (VALUE could be None, Ntlm, Ntlmi,
            Ntlmssp, Ntlmsspi, Ntlmv2, Ntlmv2i)." The default value is an empty
            string ("").
        image_link_access_protocol_type (str):
            Optional; The type of protocol to be used to access the image file.
            The options are "CIFS", "NFS", and "HTTP/S". The default value is
            "CIFS".
        image_link_access_username (str):
            Optional; The username for accessing the image file location. The
            default value is an empty string ("").
        image_link_access_password (str):
            Optional; The password for accessing the image file location. The
            default value is an empty string ("").
        image_link_vendor (str):
            Optional; The vendor of the software image. The default value is
            "Cisco".
        image_link_version (str):
            Optional; The version of the software image. See the Cisco and/or
            Intersight documentation for all the current available options. The
            default value is an empty string ("").
        image_link_supported_models (list):
            Optional; A list of the server models supported by the image file.
            The default value is None.
        image_link_description (str):
            Optional; The description of the image link to be
            created. The default value is an empty string ("").
        organization (str):
            Optional; The Intersight account organization of the image link.
            The default value is "default".
        intersight_base_url (str):
            Optional; The base URL for Intersight API paths. The default value
            is "https://www.intersight.com/api/v1". This value typically only
            needs to be changed if using the Intersight Virtual Appliance.
        tags (dict):
            Optional; The Intersight account tags that will be assigned to the
            profile template. The default value is None.
        preconfigured_api_client ("ApiClient"):
            Optional; An ApiClient class instance which handles
            Intersight client-server communication through the use of API keys.
            The default value is None. If a preconfigured_api_client argument
            is provided, empty strings ("") or None can be provided for the
            intersight_api_key_id, intersight_api_key, and intersight_base_url
            arguments.
    """
    def builder(target_object):
        """This is a function used to build the objects that are components of
        an overarching pool, policy, profile, template or related object on
        Cisco Intersight.

        Args:
            target_object (class):
                The class representing the object to be built on Intersight.

        Raises:
            Exception:
                An exception occurred due to an issue accessing the Intersight
                API path. The status code or error message will be specified.
        """
        try:
            target_object.object_maker()
        except Exception:
            print("\nA configuration error has occurred!\n")
            print("The builder function failed to configure the "
                  f"{target_object.object_type} settings.")
            print("Please check the provided arguments for the "
                  f"{target_object.object_type} settings.\n")
            print("Exception Message: ")
            traceback.print_exc()

    # Define and create SCU Image Link object in Intersight
    builder(
        ScuImageLink(
            intersight_api_key_id=intersight_api_key_id,
            intersight_api_key=intersight_api_key,
            image_link_name=image_link_name,
            image_link_file_location=image_link_file_location,
            image_link_mount_options=image_link_mount_options,
            image_link_access_protocol_type=image_link_access_protocol_type,
            image_link_access_username=image_link_access_username,
            image_link_access_password=image_link_access_password,
            image_link_description=image_link_description,
            organization=organization,
            intersight_base_url=intersight_base_url,
            tags=tags,
            preconfigured_api_client=preconfigured_api_client,
            image_link_version=image_link_version,
            image_link_vendor=image_link_vendor,
            image_link_supported_models=image_link_supported_models
            ))


# Establish classes and functions to deploy an OS Install
class OsInstallDeployment:
    """This class is used to configure an OS Install in Intersight.
    """
    object_type = "OS Install Deployment"
    intersight_api_path = "os/Installs"
    
    def __init__(
        self,
        intersight_api_key_id,
        intersight_api_key,
        os_install_target_server_id_dictionary,
        os_install_os_image_link_name,
        os_install_scu_image_link_name,
        os_install_configuration_file_source="File",
        os_install_configuration_file_location="",
        os_install_configuration_file_location_type="local",
        os_install_remove_return_from_configuration_file=True,
        os_install_target_disk_type="Virtual",
        os_install_target_disk_name="MStorBootVd",
        os_install_target_disk_storage_controller_slot="MSTOR-RAID",
        os_install_target_disk_virtual_id="0",
        os_install_target_disk_physical_serial_number="",
        os_install_method="vMedia",
        os_install_secure_boot_override=True,
        os_install_name="",
        os_install_description="",
        os_install_windows_server_edition="",
        organization="default",
        intersight_base_url="https://www.intersight.com/api/v1",
        tags=None,
        preconfigured_api_client=None
        ):
        self.intersight_api_key_id = intersight_api_key_id
        self.intersight_api_key = intersight_api_key
        self.os_install_target_server_id_dictionary = os_install_target_server_id_dictionary
        self.os_install_os_image_link_name = os_install_os_image_link_name
        self.os_install_scu_image_link_name = os_install_scu_image_link_name
        self.os_install_configuration_file_source = os_install_configuration_file_source
        self.os_install_configuration_file_location = os_install_configuration_file_location
        self.os_install_configuration_file_location_type = os_install_configuration_file_location_type
        self.os_install_remove_return_from_configuration_file = os_install_remove_return_from_configuration_file
        self.os_install_target_disk_type = os_install_target_disk_type
        self.os_install_target_disk_name = os_install_target_disk_name
        self.os_install_target_disk_storage_controller_slot = os_install_target_disk_storage_controller_slot
        self.os_install_target_disk_virtual_id = os_install_target_disk_virtual_id
        self.os_install_target_disk_physical_serial_number = os_install_target_disk_physical_serial_number
        self.os_install_method = os_install_method
        self.os_install_secure_boot_override = os_install_secure_boot_override
        self.os_install_name = os_install_name
        self.os_install_description = os_install_description
        self.os_install_windows_server_edition = os_install_windows_server_edition
        self.organization = organization
        self.intersight_base_url = intersight_base_url
        if tags is None:
            self.tags = {}
        else:
            self.tags = tags
        if preconfigured_api_client is None:
            self.api_client = get_api_client(api_key_id=intersight_api_key_id,
                                             api_secret_file=intersight_api_key,
                                             endpoint=intersight_base_url
                                             )
        else:
            self.api_client = preconfigured_api_client
        self.intersight_api_body = {
            "Description": self.os_install_description,
            "InstallMethod": self.os_install_method,
            "InstallTarget": {
                "Name": self.os_install_target_disk_name,
                "StorageControllerSlotId": self.os_install_target_disk_storage_controller_slot,
                },
            "OverrideSecureBoot": self.os_install_secure_boot_override,
            "ConfigurationFile": None,
            "AdditionalParameters": None
            }

    def __repr__(self):
        return (
            f"{self.__class__.__name__}"
            f"('{self.intersight_api_key_id}', "
            f"'{self.intersight_api_key}', "
            f"'{self.os_install_target_server_id_dictionary}', "
            f"'{self.os_install_os_image_link_name}', "
            f"'{self.os_install_scu_image_link_name}', "
            f"'{self.os_install_configuration_file_source}', "
            f"'{self.os_install_configuration_file_location}', "
            f"'{self.os_install_configuration_file_location_type}', "
            f"{self.os_install_remove_return_from_configuration_file}, "
            f"'{self.os_install_target_disk_type}', "
            f"'{self.os_install_target_disk_name}', "
            f"'{self.os_install_target_disk_storage_controller_slot}', "
            f"'{self.os_install_target_disk_virtual_id}', "
            f"'{self.os_install_target_disk_physical_serial_number}', "
            f"'{self.os_install_method}', "
            f"{self.os_install_secure_boot_override}, "
            f"'{self.os_install_name}', "
            f"'{self.os_install_description}', "
            f"'{self.os_install_windows_server_edition}', "
            f"'{self.organization}', "
            f"'{self.intersight_base_url}', "
            f"{self.tags}, "
            f"{self.api_client})"
            )

    def __str__(self):
        return f"{self.__class__.__name__} class object for '{self.os_install_target_server_id_dictionary}'"

    def _post_intersight_object(self):
        """This is a function to configure an Intersight object by
        performing a POST through the Intersight API.

        Returns:
            A string with a statement indicating whether the POST method
            was successful or failed.
            
        Raises:
            Exception:
                An exception occurred while performing the API call.
                The status code or error message will be specified.
        """
        full_intersight_api_path = f"/{self.intersight_api_path}"
        try:
            self.api_client.call_api(resource_path=full_intersight_api_path,
                                     method="POST",
                                     body=self.intersight_api_body,
                                     auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                                     )
            print(f"The configuration of the base {self.object_type} "
                  "has completed.")
            return "The POST method was successful."
        except intersight.exceptions.ApiException as error:
            if error.status == 409:
                existing_intersight_object_name = self.intersight_api_body.get("Name", "object")
                print(f"The targeted {self.object_type} appears to already "
                      "exist.")
                print("An attempt will be made to update the pre-existing "
                      f"{existing_intersight_object_name}...")
                try:
                    existing_intersight_object_moid = intersight_object_moid_retriever(intersight_api_key_id=None,
                                                                                       intersight_api_key=None,
                                                                                       object_name=existing_intersight_object_name,
                                                                                       intersight_api_path=f"{self.intersight_api_path}?$top=1000",
                                                                                       object_type=self.object_type,
                                                                                       organization=self.organization,
                                                                                       preconfigured_api_client=self.api_client
                                                                                       )
                    # Update full Intersight API path with the MOID of the existing object
                    full_intersight_api_path_with_moid = f"/{self.intersight_api_path}/{existing_intersight_object_moid}"
                    self.api_client.call_api(resource_path=full_intersight_api_path_with_moid,
                                             method="POST",
                                             body=self.intersight_api_body,
                                             auth_settings=['cookieAuth', 'http_signature', 'oAuth2', 'oAuth2']
                                             )
                    print(f"The update of the {self.object_type} has "
                          "completed.")
                    print(f"The pre-existing {existing_intersight_object_name} "
                          "has been updated.")
                    return "The POST method was successful."
                except Exception:
                    print("\nA configuration error has occurred!\n")
                    print(f"Unable to update the {self.object_type} under the "
                          "Intersight API resource path "
                          f"'{full_intersight_api_path_with_moid}'.\n")
                    print(f"The pre-existing {existing_intersight_object_name} "
                          "could not be updated.")
                    print("Exception Message: ")
                    traceback.print_exc()
                    return "The POST method failed."
            else:
                print("\nA configuration error has occurred!\n")
                print(f"Unable to configure the {self.object_type} under the "
                      "Intersight API resource path "
                      f"'{full_intersight_api_path}'.\n")
                print("Exception Message: ")
                traceback.print_exc()
                return "The POST method failed."
        except Exception:
            print("\nA configuration error has occurred!\n")
            print(f"Unable to configure the {self.object_type} under the "
                  "Intersight API resource path "
                  f"'{full_intersight_api_path}'.\n")
            print("Exception Message: ")
            traceback.print_exc()
            return "The POST method failed."

    def _update_api_body_general_attributes(self):
        """This function updates the Intersight API body with general
        attributes for the Intersight object.
        """
        # Retrieve the Intersight Organization MOID
        os_install_organization_moid = intersight_object_moid_retriever(
            intersight_api_key_id=None,
            intersight_api_key=None,
            object_name=self.organization,
            intersight_api_path="organization/Organizations?$top=1000",
            object_type="Organization",
            preconfigured_api_client=self.api_client
            )
        # Update the API body with the Intersight Organization MOID
        self.intersight_api_body["Organization"] = {"Moid": os_install_organization_moid}
        # Create the Intersight Tags dictionary list
        tags_dictionary_list = []
        if self.tags:
            for key in self.tags:
                tags_dictionary_list_entry = {
                    "Key": key,
                    "Value": self.tags.get(key)
                    }
                tags_dictionary_list.append(tags_dictionary_list_entry)
        # Update the API body with the Intersight Tags dictionary list
        self.intersight_api_body["Tags"] = tags_dictionary_list

    def _update_api_body_os_install_target_disk_type(self):
        """This function updates the Intersight API body with the OS Install Target Disk Type
        i.e. target platform in the accepted format.
        
        Raises:
            Exception:
                An exception occurred while reformatting a provided value for
                an attribute. The issue will likely be due to the provided
                value not being in string format. Changing the value to string
                format should resolve the exception.
        """    
        # Update the API body with the provided OS Install Target Disk Type
        # Reformat the user provided os_install_target_disk_type variable value to lowercase and remove spaces to prevent potential format issues
        try:
            reformatted_os_install_target_disk_type_variable_value = "".join(self.os_install_target_disk_type.lower().split())
        except Exception:
            print("\nA configuration error has occurred!\n")
            print(f"During the configuration of the {self.object_type} named "
                  f"{self.policy_name}, there was an issue with the value "
                  "provided for the OS Install Target Disk Type setting.")
            print(f"The value provided was {os_install_target_disk_type}.")
            print("To proceed, the value provided for the OS Install Target "
                  "Disk Type setting should be updated to an accepted "
                  "string format.")
            print("The accepted values are 'Virtual' and 'Physical'.")
            print("Please update the configuration, then re-attempt "
                  "execution.\n")
            sys.exit(0)
        if reformatted_os_install_target_disk_type_variable_value == "virtual":
            self.intersight_api_body["InstallTarget"]["ObjectType"] = "os.VirtualDrive"
        elif reformatted_os_install_target_disk_type_variable_value == "physical":
            self.intersight_api_body["InstallTarget"]["ObjectType"] = "os.PhysicalDisk"
        else:
            print("\nA configuration error has occurred!\n")
            print(f"During the configuration of the {self.object_type} named "
                  f"{self.policy_name}, there was an issue with the value "
                  "provided for the OS Install Target Disk Type setting.")
            print(f"The value provided was {os_install_target_disk_type}.")
            print("To proceed, the value provided for the OS Install Target "
                  "Disk Type setting should be updated to an accepted "
                  "string format.")
            print("The accepted values are 'Virtual' and 'Physical'.")
            print("Please update the configuration, then re-attempt "
                  "execution.\n")
            sys.exit(0)

    def object_preparation(self):
        """This function prepares the targeted policy object with all components
        needed for the complete API body.
        """
        # Capture Target Server ID info
        os_install_target_server_id = self.os_install_target_server_id_dictionary.get("Server Identifier")
        os_install_target_server_form_factor = self.os_install_target_server_id_dictionary.get("Server Form Factor", "Blade")
        os_install_target_server_connection_type = self.os_install_target_server_id_dictionary.get("Server Connection Type", "FI-Attached")
        print(f"\nConfiguring the {self.object_type} for the target server ID: "
              f"{os_install_target_server_id}...")
        # Update the API body with general attributes
        self._update_api_body_general_attributes()
        # Update the API body with the provided Target Server MOID and related data
        os_install_target_server_moid_and_data = retrieve_target_server_data(
            intersight_api_key_id=None,
            intersight_api_key=None,
            server_identifier=os_install_target_server_id,
            server_form_factor=os_install_target_server_form_factor,
            server_connection_type=os_install_target_server_connection_type,
            preconfigured_api_client=self.api_client
            )
        self.intersight_api_body["Server"] = os_install_target_server_moid_and_data
        # Update the API body with the OS Image Link Moid and related data
        os_install_os_image_link_name_moid = intersight_object_moid_retriever(
            intersight_api_key_id=None,
            intersight_api_key=None,
            object_name=self.os_install_os_image_link_name,
            intersight_api_path="softwarerepository/OperatingSystemFiles?$top=1000",
            object_type="OS Image Link",
            organization=self.organization,
            preconfigured_api_client=self.api_client
            )
        self.intersight_api_body["Image"] = {
            "ClassId": "mo.MoRef",
            "Moid": os_install_os_image_link_name_moid,
            "ObjectType": "softwarerepository.OperatingSystemFile",
            "link": f"{self.intersight_base_url}/softwarerepository/OperatingSystemFiles/{os_install_os_image_link_name_moid}"
            }
        # Update the API body with the SCU Image Link Moid and related data
        os_install_scu_image_link_name_moid = intersight_object_moid_retriever(
            intersight_api_key_id=None,
            intersight_api_key=None,
            object_name=self.os_install_scu_image_link_name,
            intersight_api_path="firmware/ServerConfigurationUtilityDistributables?$top=1000",
            object_type="SCU Image Link",
            organization=self.organization,
            preconfigured_api_client=self.api_client
            )
        self.intersight_api_body["OsduImage"] = {
            "ClassId": "mo.MoRef",
            "Moid": os_install_scu_image_link_name_moid,
            "ObjectType": "firmware.ServerConfigurationUtilityDistributable",
            "link": f"{self.intersight_base_url}/firmware/ServerConfigurationUtilityDistributables/{os_install_scu_image_link_name_moid}"
            }
        # Update the API body with the provided Configuration File depending on the provided Configuration Source
        if self.os_install_configuration_file_source == "File":
            os_install_configuration_file_data = load_configuration_file(
                configuration_file_location=self.os_install_configuration_file_location,
                configuration_file_location_type=self.os_install_configuration_file_location_type,
                remove_return_from_configuration_file=self.os_install_remove_return_from_configuration_file
                )
            self.intersight_api_body["Answers"] = {
                "AnswerFile": os_install_configuration_file_data,
                "Source": "File"
                }
        else:
            self.intersight_api_body["Answers"] = {
                "Source": "Embedded"
                }
        # Update the API body with the OS Install Target Disk Type
        self._update_api_body_os_install_target_disk_type()
        # Update the API body with any provided Installation Target Disk Storage Settings depending on disk type
        updated_os_install_target_disk_type = self.intersight_api_body.get("InstallTarget", {}).get("ObjectType")
        if updated_os_install_target_disk_type == "os.VirtualDrive":
            self.intersight_api_body["InstallTarget"]["Id"] = self.os_install_target_disk_virtual_id
        if updated_os_install_target_disk_type == "os.PhysicalDisk":
            self.intersight_api_body["InstallTarget"]["SerialNumber"] = self.os_install_target_disk_physical_serial_number
        # Update the API body with any provided OS Install Name
        if self.os_install_name:
            self.intersight_api_body["Name"] = self.os_install_name
        # Update the API body with any provided Microsoft Windows Server Edition
        if self.os_install_windows_server_edition:
            self.intersight_api_body["OperatingSystemParameters"] = {
                "ObjectType": "os.WindowsParameters",
                "Edition": self.os_install_windows_server_edition
                }

    def object_maker(self):
        """This function makes the targeted policy object.
        """
        # Prepare the API body
        self.object_preparation()
        # POST the API body to Intersight
        self._post_intersight_object()


def deploy_os_install(
    intersight_api_key_id,
    intersight_api_key,
    os_install_target_server_id_dictionary,
    os_install_os_image_link_name,
    os_install_scu_image_link_name,
    os_install_configuration_file_source,
    os_install_configuration_file_location,
    os_install_configuration_file_location_type="local",
    os_install_remove_return_from_configuration_file=True,
    os_install_target_disk_type="Virtual",
    os_install_target_disk_name="MStorBootVd",
    os_install_target_disk_storage_controller_slot="MSTOR-RAID",
    os_install_target_disk_virtual_id="0",
    os_install_target_disk_physical_serial_number="",
    os_install_method="vMedia",
    os_install_secure_boot_override=True,
    os_install_name="",
    os_install_description="",
    os_install_windows_server_edition="",
    organization="default",
    intersight_base_url="https://www.intersight.com/api/v1",
    tags=None,
    preconfigured_api_client=None
    ):
    """This is a function used to add an Operating System (OS) Image Link on
    Cisco Intersight.

    Args:
        intersight_api_key_id (str):
            The ID of the Intersight API key.
        intersight_api_key (str):
            The system file path of the Intersight API key.
        os_install_target_server_id_dictionary (dict):
            A dictionary containing the target server data. Required keys
            include "Server Identifier", "Server Form Factor", and
            "Server Connection Type". For the "Server Identifier" key, the
            accepted values are the Server serial, name, model, or PID
            (product ID). This information can be found in Intersight, if
            needed. For the "Server Form Factor" key, the options are "Blade or
            "Rack". For the "Server Connection Type" key, the options are
            "FI-Attached" or "Standalone".
        os_install_os_image_link_name (str):
            The name of the OS image link.
        os_install_scu_image_link_name (str):
            The name of the SCU image link.
        os_install_configuration_file_source (str):
            Optional; The source of the configuration file. Available options
            are "File" for a local custom file or "Embedded" for a 
            configuration file that is embedded into the provided OS image. The
            default value is "File".
        os_install_configuration_file_location (str):
            Optional; The location of the configuration file. The default value
            is an empty string ("").
        os_install_configuration_file_location_type (str):
            Optional; The location type for the configuration file. Available
            options are "local" for local file paths and "http" for access over 
            a URL. The default value is "local".
        os_install_remove_return_from_configuration_file (bool):
            Optional; The option to remove any instance of '\r' from the
            content of the configuration file. The default value is True.
        os_install_target_disk_type (str):
            Optional; The type of disk to be used for the target installation.
            The options are "Virtual" and "Physical". The default value is
            "Virtual".
        os_install_target_disk_name (str):
            Optional; The name of the target disk. The default value is
            "MStorBootVd".
        os_install_target_disk_storage_controller_slot (str):
            Optional; The target disk storage controller slot. Available
            options include "MSTOR-RAID", "MRAID", "FMEZZ1-SAS", Etc. See
            Intersight docs for more options. The default value is "MSTOR-RAID".
        os_install_target_disk_virtual_id (str):
            Optional; The ID for the target disk. This value is only used for
            virtual target disks. The default value is "0".
        os_install_target_disk_physical_serial_number (str):
            Optional; The serial number for the target disk. This value is only
            used for physical target disks. The default value is an empty
            string ("").
        os_install_method (str):
            Optional; The OS install method. Currently the only supported
            by Intersight is "vMedia". Additional options to be supported in
            the future include iPXE. The default value is "vMedia".
        os_install_secure_boot_override (bool):
            Optional; The option to enable secure boot override. The default
            value is True.
        os_install_name (str):
            Optional; The name of the OS install deployment. The default value
            is an empty string ("").
        os_install_description (str):
            Optional; The description of the OS install deployment. The default
            value is an empty string ("").
        os_install_windows_server_edition (str):
            Optional; The Windows server edition, if installing the Microsoft
            Windows Server OS. Available options include "Standard",
            "Datacenter", "StandardCore", and "DatacenterCore". The default
            value is "Datacenter".
        organization (str):
            Optional; The Intersight account organization of the OS install
            deployment. The default value is "default".
        intersight_base_url (str):
            Optional; The base URL for Intersight API paths. The default value
            is "https://www.intersight.com/api/v1". This value typically only
            needs to be changed if using the Intersight Virtual Appliance.
        tags (dict):
            Optional; The Intersight account tags that will be assigned to the
            profile template. The default value is None.
        preconfigured_api_client ("ApiClient"):
            Optional; An ApiClient class instance which handles
            Intersight client-server communication through the use of API keys.
            The default value is None. If a preconfigured_api_client argument
            is provided, empty strings ("") or None can be provided for the
            intersight_api_key_id, intersight_api_key, and intersight_base_url
            arguments.
    """
    def builder(target_object):
        """This is a function used to build the objects that are components of
        an overarching pool, policy, profile, template or related object on
        Cisco Intersight.

        Args:
            target_object (class):
                The class representing the object to be built on Intersight.

        Raises:
            Exception:
                An exception occurred due to an issue accessing the Intersight
                API path. The status code or error message will be specified.
        """
        try:
            target_object.object_maker()
        except Exception:
            print("\nA configuration error has occurred!\n")
            print("The builder function failed to configure the "
                  f"{target_object.object_type} settings.")
            print("Please check the provided arguments for the "
                  f"{target_object.object_type} settings.\n")
            print("Exception Message: ")
            traceback.print_exc()

    # Define and create SCU Image Link object in Intersight
    builder(
        OsInstallDeployment(
            intersight_api_key_id=intersight_api_key_id,
            intersight_api_key=intersight_api_key,
            os_install_target_server_id_dictionary=os_install_target_server_id_dictionary,
            os_install_os_image_link_name=os_install_os_image_link_name,
            os_install_scu_image_link_name=os_install_scu_image_link_name,
            os_install_configuration_file_source=os_install_configuration_file_source,
            os_install_configuration_file_location=os_install_configuration_file_location,
            os_install_configuration_file_location_type=os_install_configuration_file_location_type,
            os_install_remove_return_from_configuration_file=os_install_remove_return_from_configuration_file,
            os_install_target_disk_type=os_install_target_disk_type,
            os_install_target_disk_name=os_install_target_disk_name,
            os_install_target_disk_storage_controller_slot=os_install_target_disk_storage_controller_slot,
            os_install_target_disk_virtual_id=os_install_target_disk_virtual_id,
            os_install_target_disk_physical_serial_number=os_install_target_disk_physical_serial_number,
            os_install_method=os_install_method,
            os_install_secure_boot_override=os_install_secure_boot_override,
            os_install_name=os_install_name,
            os_install_description=os_install_description,
            os_install_windows_server_edition=os_install_windows_server_edition,
            organization=organization,
            intersight_base_url=intersight_base_url,
            tags=tags,
            preconfigured_api_client=preconfigured_api_client
            ))


def main():
    # Establish Intersight OS Installer specific variables
    deployment_type = "Automated OS Install Tool"
    
    # Establish Intersight SDK for Python API client instance
    main_intersight_api_client = get_api_client(api_key_id=key_id,
                                                api_secret_file=key,
                                                endpoint=intersight_base_url,
                                                url_certificate_verification=url_certificate_verification
                                                )
    
    # Starting the Intersight OS Installer for Cisco Intersight
    print(f"\nStarting the {deployment_type} for Cisco Intersight.\n")

    # Run the Intersight API and Account Availability Test
    print("Running the Intersight API and Account Availability Test.")
    test_intersight_api_service(
        intersight_api_key_id=None,
        intersight_api_key=None,
        preconfigured_api_client=main_intersight_api_client
        )

    # Create the OS Image Link in Intersight if selected
    add_os_image_link(
        intersight_api_key_id=None,
        intersight_api_key=None,
        image_link_name=os_image_link_name,
        image_link_file_location=os_image_link_file_location,
        image_link_mount_options=os_image_link_mount_options,
        image_link_access_protocol_type=os_image_link_access_protocol_type,
        image_link_access_username=os_image_link_access_username,
        image_link_access_password=os_image_link_access_password,
        image_link_vendor=os_image_link_vendor,
        image_link_version=os_image_link_version,
        image_link_description=os_image_link_description,
        organization=os_install_organization,
        intersight_base_url=intersight_base_url,
        tags=os_install_tags,
        preconfigured_api_client=main_intersight_api_client
        )

    # Create the SCU Image Link in Intersight if selected
    add_scu_image_link(
        intersight_api_key_id=None,
        intersight_api_key=None,
        image_link_name=scu_image_link_name,
        image_link_file_location=scu_image_link_file_location,
        image_link_mount_options=scu_image_link_mount_options,
        image_link_access_protocol_type=scu_image_link_access_protocol_type,
        image_link_access_username=scu_image_link_access_username,
        image_link_access_password=scu_image_link_access_password,
        image_link_version=scu_image_link_version,
        image_link_supported_models=scu_image_link_supported_models,
        image_link_description=scu_image_link_description,
        organization=os_install_organization,
        intersight_base_url=intersight_base_url,
        tags=os_install_tags,
        preconfigured_api_client=main_intersight_api_client
        )

    # Determine OS Image for OS Install
    if pre_loaded_os_image_link:
        os_install_os_image_link_name = pre_loaded_os_image_link_name
    else:
        os_install_os_image_link_name = os_image_link_name

    # Determine SCU Image for OS Install
    if pre_loaded_scu_image_link:
        os_install_scu_image_link_name = pre_loaded_scu_image_link
    else:
        os_install_scu_image_link_name = scu_image_link_name

    # Deploy the OS Install
    deploy_os_install(
        intersight_api_key_id=None,
        intersight_api_key=None,
        os_install_target_server_id_dictionary=os_install_target_server_id_dictionary,
        os_install_os_image_link_name=os_install_os_image_link_name,
        os_install_scu_image_link_name=os_install_scu_image_link_name,
        os_install_configuration_file_source=os_install_configuration_file_source,
        os_install_configuration_file_location=os_install_configuration_file_location,
        os_install_configuration_file_location_type=os_install_configuration_file_location_type,
        os_install_remove_return_from_configuration_file=os_install_remove_return_from_configuration_file,
        os_install_target_disk_type=os_install_target_disk_type,
        os_install_target_disk_name=os_install_target_disk_name,
        os_install_target_disk_storage_controller_slot=os_install_target_disk_storage_controller_slot,
        os_install_target_disk_virtual_id=os_install_target_disk_virtual_id,
        os_install_target_disk_physical_serial_number=os_install_target_disk_physical_serial_number,
        os_install_method=os_install_method,
        os_install_secure_boot_override=os_install_secure_boot_override,
        os_install_name=os_install_name,
        os_install_description=os_install_description,
        os_install_windows_server_edition=os_install_windows_server_edition,
        organization=os_install_organization,
        intersight_base_url=intersight_base_url,
        tags=os_install_tags,
        preconfigured_api_client=main_intersight_api_client
        )

    # Intersight OS Installer completion
    print(f"\nThe {deployment_type} has completed.\n")


if __name__ == "__main__":
    main()

# Exiting the Intersight OS Installer for Cisco Intersight
sys.exit(0)

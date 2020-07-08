from deepsecurity.api_client import ApiClient as api_client

import urllib3
import os
import json
from pprint import pprint
from datetime import datetime
import requests
import traceback

from _api_client import DSApiClient
import _func


def main(dsapi=DSApiClient()):
    computer_property_file = os.path.join(os.path.dirname(
        os.path.abspath(__file__)), 'computer_properties.json')
    #_func.policies_operation(dsapi, 'computer_properties.json')
    _func.policies_dump(
        dsapi=dsapi, computer_property_file=computer_property_file, update=False)


if __name__ == '__main__':
    main()

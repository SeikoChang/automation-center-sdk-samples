from deepsecurity.api_client import ApiClient as api_client

import urllib3
import os
import json
from pprint import pprint
from datetime import datetime
import requests

from _api_client import DSApiClient
import _func


def main(dsapi=DSApiClient()):
    _func.policies_generation(dsapi, 'computer_properties.json')

if __name__ == '__main__':
    main()


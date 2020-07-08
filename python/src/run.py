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
    #_func.policies_operation(dsapi, 'computer_properties.json')
    _func.policies_dump(dsapi, 'computer_properties.json')


if __name__ == '__main__':
    main()

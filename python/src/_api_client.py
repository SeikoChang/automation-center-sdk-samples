import sys
import inspect
import os
import json
import requests
import six
from pprint import pprint
from datetime import datetime

import deepsecurity as api
#from deepsecurity.api_client import ApiClient
from deepsecurity.configuration import Configuration
from deepsecurity.rest import ApiException as api_exception

dsm_property = 'dsm_properties.json'
computer_property = 'computer_properties.json'

import urllib3
from urllib3.exceptions import InsecureRequestWarning, InsecurePlatformWarning

urllib3.disable_warnings(InsecureRequestWarning)
urllib3.disable_warnings(InsecurePlatformWarning)



class DSApiClient(api.ApiClient):
    def __init__(self, configuration=None):
        self.api = api
        self.api_exception = api_exception

        self.configuration = configuration or self.generate_configuration()

        super(DSApiClient, self).__init__(configuration=self.configuration)

        dsm_property_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), dsm_property)
        computer_property_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), computer_property)

        self.dsm_properties = self.load_property(dsm_property_file)
        self.computer_properties = self.load_property(computer_property_file)

        self.computer = self.load_property_key(self.computer_properties, 'computer')
        self.computer_id = self.load_property_key(self.computer_properties, 'computer_id')
        self.policy_id = self.load_property_key(self.computer_properties, 'policy_id')
        self.default_api_version = self.load_property_key(self.dsm_properties, 'default_api_version')

        ### Auto load APIs as self.XXXApi
        '''
        for name, obj in inspect.getmembers(sys.modules["deepsecurity"]):
            if inspect.isclass(obj) and name.endswith("Api"):
                exec("from deepsecurity import %s" % name)
                #print("from deepsecurity import %s" % name)
                exec("self.%s = %s(self)" %(name, name))
                #print("self.%s = %s(self)" %(name, name))
        '''

    def _create_api_key(self, url, session):
        import time

        timestr = datetime.now().strftime("%Y%m%d.%H:%M:%S.%f")
        time_to_expiry_in_ms = 1 * 24 * 60 * 60 * 1000
        current_time_in_ms = int(round(time.time() * 1000))

        header = {"API-Version": "v1",
                    "Content-Type": "application/json",
                    "RID": session['rid'],
                    "Cookie": "sid={}".format(session['sid'])}

        payload = {
            "keyName": "auto_generated_by_PIT_on_%s" % timestr,
            "description": "Master API Key Auto Generated by PTI and Created on %s" % timestr,
            "locale": "en-US",
            "roleID": 1,
            "timeZone": "Asia/Taipei",
            "active": True,
            "expiryDate": current_time_in_ms + time_to_expiry_in_ms # expires in 1 day
        }

        #print("header: %s, payload: %s" % (header, payload))
        result = requests.post(url + "/apikeys",
                                headers=header, 
                                data=json.dumps(payload), 
                                verify=False)
        #print("status_code: %s" % result.status_code)
        #print("content: %s" % result.text)
        api_key = result.json()["secretKey"]
        #print('API Key is %s' % api_key)
        return api_key

    def _create_session(self, url, username, password):
        header = {"API-Version": "v1", "Content-Type": "application/json"}
        payload = {"userName": username, "password": password}
        result = requests.post(url + "/sessions",
                                headers=header,
                                data=json.dumps(payload),
                                verify=False)
        #print("status_code: %s" % result.status_code)
        #print("content: %s" % result.text)
        rid, sid = result.json()["RID"], result.cookies.get_dict()['sID']
        #print("rid: {}, sid: {}".format(rid, sid))

        return {'rid':rid, 'sid':sid}

    def end_session(self):
        if self.sid is not None and self.rid is not None:
            header = {"API-Version": "v1",
                      "Content-Type": "application/json",
                      "RID": self.rid,
                      "Cookie": "sid={sid}".format(sid=self.sid)}
            result = requests.delete(self.url + "/sessions/current", headers=header, verify=False)
            #print("status_code: %s" % result.status_code, flush=True)
            print("status_code: {}".format(result.status_code))
            return result
        else:
            return {"warning": "Please make sure you had created the session."}

    def load_property(self, property_file):
        with open(property_file) as raw_properties:
            properties = json.load(raw_properties)

        return properties

    def load_property_key(self, properties, key, default=None):
        return properties.get(key, default)

    def generate_configuration(self):
        configuration = Configuration()

        # Get the DSM URL and API key from a JSON file
        dsm_property_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), dsm_property)

        with open(dsm_property_file) as raw_properties:
            dsm_properties = json.load(raw_properties)

        url = dsm_properties.get('url', None)
        username = dsm_properties.get('userName', None)
        password = dsm_properties.get('password', None)
        host = dsm_properties.get('host', None)
        port = dsm_properties.get('port', None)
        self.secret_key = dsm_properties.get('secretkey', None)

        if not url:
            url = "https://{}:{}/api".format(host, port)

        configuration.host = url
        session = None
        if not self.secret_key:
            self.session = self._create_session(url, username, password)
            self.sid = self.session['sid']
            self.rid = self.session['rid']
            self.secret_key = self._create_api_key(url, self.session)

        configuration.api_key['api-secret-key'] = self.secret_key
        configuration.host = url
        configuration.username = username
        configuration.password = password

        #pprint(vars(configuration))
        return configuration


from urllib3.exceptions import InsecureRequestWarning, InsecurePlatformWarning
import urllib3
import sys
import inspect
import os
import json
import requests
import six
import suds
import traceback
from pprint import pprint
from datetime import datetime

import deepsecurity as api
#from deepsecurity.api_client import ApiClient
from deepsecurity.configuration import Configuration
from deepsecurity.rest import ApiException as api_exception

dsm_property = 'dsm_properties.json'
computer_property = 'computer_properties.json'


urllib3.disable_warnings(InsecureRequestWarning)
urllib3.disable_warnings(InsecurePlatformWarning)


class DSApiClient(api.ApiClient):
    def __init__(self, configuration=None, dsm_property='dsm_properties.json', computer_property='computer_properties.json'):
        self.api = api
        self.api_exception = api_exception

        self.configuration = configuration or self.generate_configuration()

        super(DSApiClient, self).__init__(configuration=self.configuration)

        dsm_property_file = os.path.join(os.path.dirname(
            os.path.abspath(__file__)), dsm_property)
        #dsm_property_file = dsm_property
        if not os.path.exists(dsm_property_file):
            raise Exception(
                'exception due to dsm propery file = %s not found' % dsm_property_file)

        computer_property_file = os.path.join(os.path.dirname(
            os.path.abspath(__file__)), computer_property)
        #computer_property_file = computer_property
        if not os.path.exists(computer_property_file):
            raise Exception(
                'exception due to configuration propery file = %s not found' % computer_property_file)

        self.dsm_properties = self.load_property(dsm_property_file)
        self.computer_properties = self.load_property(computer_property_file)

        self.computer = self.load_property_key(
            self.computer_properties, 'computer')
        self.computer_id = self.load_property_key(
            self.computer_properties, 'computer_id')
        self.policy_id = self.load_property_key(
            self.computer_properties, 'policy_id')
        self.default_api_version = self.load_property_key(
            self.dsm_properties, 'default_api_version')

        # Auto load APIs as self.XXXApi
        '''
        for name, obj in inspect.getmembers(sys.modules["deepsecurity"]):
            if inspect.isclass(obj) and name.endswith("Api"):
                exec("from deepsecurity import %s" % name)
                #print("from deepsecurity import %s" % name)
                exec("self.%s = %s(self)" %(name, name))
                #print("self.%s = %s(self)" %(name, name))
        '''

    def load_property(self, property_file):
        with open(property_file) as raw_properties:
            properties = json.load(raw_properties)

        return properties

    def load_property_key(self, properties, key, default=None):
        return properties.get(key, default)

    def generate_configuration(self):
        configuration = Configuration()

        # Get the DSM URL and API key from a JSON file
        dsm_property_file = os.path.join(os.path.dirname(
            os.path.abspath(__file__)), dsm_property)

        with open(dsm_property_file) as raw_properties:
            dsm_properties = json.load(raw_properties)

        configuration.host = dsm_properties.get('url', None)
        self.tenantAccount = dsm_properties.get('tenantAccount', None)
        self.tenantID = dsm_properties.get('tenantID', None)
        configuration.username = dsm_properties.get('userName', None)
        configuration.username = dsm_properties.get('userName', None)
        configuration.password = dsm_properties.get('password', None)
        self.host = dsm_properties.get('host', None)
        self.port = dsm_properties.get('port', None)
        self.secret_key = dsm_properties.get('secretkey', None)

        if not configuration.host:
            configuration.host = "https://{host}:{port}/api".format(
                host=self.host, port=self.port)

        if not self.secret_key:
            self.session = self.create_session(configuration)
            self.sid = self.session['sid']
            self.rid = self.session['rid']
            self.secret_key = self.create_api_key(configuration)
            if self.tenantAccount and self.tenantID:
                self.secret_key = self.create_api_key(
                    configuration, tenant=True)

        configuration.api_key['api-secret-key'] = self.secret_key

        # pprint(vars(configuration))
        return configuration

    def create_session(self, configuration):
        header = {"API-Version": "v1", "Content-Type": "application/json"}
        payload = {"userName": configuration.username,
                   "password": configuration.password}

        #print("payload: %s" % payload)
        result = requests.post(configuration.host + "/sessions",
                               headers=header,
                               data=json.dumps(payload),
                               verify=False)
        #print("status_code: %s" % result.status_code)
        #print("content: %s" % result.text)
        rid, sid = result.json()["RID"], result.cookies.get_dict()['sID']
        #print("rid: {}, sid: {}".format(rid, sid))

        return {'rid': rid, 'sid': sid}

    def end_session(self):
        if self.sid is not None and self.rid is not None:
            header = {"API-Version": "v1",
                      "Content-Type": "application/json",
                      "RID": self.rid,
                      "Cookie": "sid={sid}".format(sid=self.sid)}
            result = requests.delete(
                self.url + "/sessions/current", headers=header, verify=False)
            #print("status_code: %s" % result.status_code, flush=True)
            print("status_code: {}".format(result.status_code))
            return result
        else:
            return {"warning": "Please make sure you had created the session."}

    def get_DSM_WSDL(self, configuration):
        DSM_URL = 'https://{ip}:{port}'.format(ip=self.host, port=self.port)

        try:
            print('Connecting to %s' % DSM_URL)
            self.dsm = suds.client.Client(DSM_URL + '/webservice/Manager?WSDL')
            if self.tenantAccount:
                self.sID = dsm.service.authenticateTenant(
                    self.tenantAccount, configuration.username, configuration.password)
            else:
                self.sID = dsm.service.authenticate(
                    configuration.username, configuration.password)
            print('%s: %s' % ('Login DSM'.ljust(20), '[ OK ]'))
        except:
            print('%s: %s' % ('Login DSM'.ljust(20), '[ ERROR ]'))
            print('DSM service might not available.')
            self.dsm = self.sID = None

        return self.dsm, self.sID

    def close_DSM_WSDL(self):
        rtv = None
        if all([self.dsm, self.sID]):
            try:
                rtv = dsm.service.endSession(self.sID)
            except:
                print('Generic Exception: ' + traceback.format_exc())

        return rtv

    def create_api_key(self, configuration, tenant=False):
        import time

        timestr = datetime.now().strftime("%Y%m%d.%H:%M:%S.%f")
        time_to_expiry_in_ms = 1 * 24 * 60 * 60 * 1000
        current_time_in_ms = int(round(time.time() * 1000))

        header = {"API-Version": "v1",
                  "Content-Type": "application/json",
                  "RID": self.session['rid'],
                  "Cookie": "sid={}".format(self.session['sid'])}

        payload = {
            "keyName": "auto_generated_by_PIT_on_%s" % timestr,
            "description": "API Key Auto Generated by PIT and Created on %s" % timestr,
            "locale": "en-US",
            "roleID": 1,
            "timeZone": "Asia/Taipei",
            "active": True,
            "expiryDate": current_time_in_ms + time_to_expiry_in_ms  # expires in 1 day
        }

        #print("header: %s, payload: %s" % (header, payload))
        if tenant and self.tenantID:
            path = "{host}/tenants/{tenantID}/apikeys".format(
                host=configuration.host, tenantID=self.tenantID)
        else:
            path = "{host}/apikeys".format(host=configuration.host)
        # print(path)
        result = requests.post(path,
                               headers=header,
                               data=json.dumps(payload),
                               verify=False)
        #print("status_code: %s" % result.status_code)
        #print("content: %s" % result.text)
        api_key = result.json()["secretKey"]
        #print('API Key is %s' % api_key)
        return api_key

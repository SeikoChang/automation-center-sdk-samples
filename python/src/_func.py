# Copyright 2019 Trend Micro.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from pprint import pprint
import json
import os
import time
import traceback


from _utility import json_serial
from _utility import merge_dicts
#from _utility import get_attr_from_config
#from _utility import setattr_from_attribute_map
from _utility import serializ
from _utility import deserialize_from_object
from deepsecurity.rest import RESTResponse, RESTClientObject


obj_contained_id_map = {
    'policies': ['integrityMonitoring', 'applicationControl', 'firewall', 'webReputation', 'logInspection', 'antiMalware8'],
    'antiMalware': ['manualScanConfigurationID', 'scheduledScanConfigurationID', 'realTimeScanScheduleID', 'realTimeScanConfigurationID'],
    'antiMalwareConfigurations': ['directoryListID', 'excludedDirectoryListID', 'excludedFileListID', 'excludedProcessImageFileListID', 'excludedFileExtensionListID', 'fileExtensionListID']
}

denpendecy_map = {
    'manualScanConfigurationID':'antiMalwareConfigurations',
    'scheduledScanConfigurationID':'antiMalwareConfigurations',
    'realTimeScanScheduleID':'schedules',
    'realTimeScanConfigurationID':'antiMalwareConfigurations',
    'directoryListID':'directoryLists',
    'excludedDirectoryListID':'directoryLists',
    'excludedFileListID':'fileLists',
    'excludedProcessImageFileListID':'fileLists',
    'excludedFileExtensionListID':'fileExtensionLists',
    'fileExtensionListID':'fileExtensionLists'
}

obj_to_id_map = {
    'antiMalwareConfigurations': ['manualScanConfigurationID', 'scheduledScanConfigurationID', 'realTimeScanConfigurationID'],
    'schedules': ['realTimeScanScheduleID'],
    'directoryLists': ['directoryListID', 'excludedDirectoryListID'],
    'fileLists': ['excludedFileListID', 'excludedProcessImageFileListID'],
    'fileExtensionLists' : ['excludedFileExtensionListID', 'fileExtensionListID']
}

obj_order = [
    'schedules', 
    'fileExtensionLists', 
    'directoryLists', 
    'fileLists', 
    'antiMalwareConfigurations', 
    'policies']

objs_to_list_obj = {
    'schedules': 'list[Schedules]',
    'fileExtensionLists': 'list[FileExtensionLists]',
    'directoryLists': 'list[DirectoryLists]',
    'fileLists': 'list[FileList]',
    'antiMalwareConfigurations': 'list[AntiMalwareConfigurations]',
    'policies': 'list[Policies]',
    #'computers': 'list[Computers]',
}

objs_to_objs_function = {
    'schedules': 'update_or_create_schedules_to_dsm',
    'fileExtensionLists': 'update_or_create_file_extension_lists_to_dsm',
    'directoryLists': 'update_or_create_directory_lists_to_dsm',
    'fileLists': 'update_or_create_file_lists_to_dsm',
    'antiMalwareConfigurations': 'update_or_create_anti_malware_to_dsm',
    'policies': 'update_or_create_policy_to_dsm',
    #'computers': 'update_or_create_computer_to_dsm',
}

objs_to_obj_klass = {
    'schedules': 'Schedule',
    'fileExtensionLists': 'FileExtensionList',
    'directoryLists': 'DirectoryList',
    'fileLists': 'FileList',
    'antiMalwareConfigurations': 'AntiMalwareConfiguration',
    'policies': 'Policy',
    #'computers': 'Computer',
}

objs_to_objs_klass = {
    'schedules': 'Schedules',
    'fileExtensionLists': 'FileExtensionLists',
    'directoryLists': 'DirectoryLists',
    'fileLists': 'FileLists',
    'antiMalwareConfigurations': 'AntiMalwareConfigurations',
    'policies': 'Policies',
    #'computers': 'Computers',
}

objs_to_obj_method = {
    'schedules': 'schedule',
    'fileExtensionLists': 'file_extension_list',
    'directoryLists': 'directory_list',
    'fileLists': 'file_list',
    'antiMalwareConfigurations': 'anti_malware',
    'policies': 'policy',
    #'computers': 'computer',
}

objs_to_objs_method = {
    'schedules': 'schedules',
    'fileExtensionLists': 'file_extension_lists',
    'directoryLists': 'directory_lists',
    'fileLists': 'file_lists',
    'antiMalwareConfigurations': 'anti_malwares',
    'policies': 'policies',
    #'computers': 'computers',
}

objs_to_objs_properties = {
    'schedules': 'schedules',
    'fileExtensionLists': 'file_extension_lists',
    'directoryLists': 'directory_lists',
    'fileLists': 'file_lists',
    'antiMalwareConfigurations': 'anti_malware_configurations',
    'policies': 'policies',
    #'computers': 'computers',
}


def setattr_from_attribute_map(object, attribute_map):
    for k, v in getattr(object, attribute_map).items():
        #print(k, v)
        try:
            setattr(object, k, eval(v))
            #print('[%s] = %s ' % (k, eval(v)))
        except:
            # bybass those attribute not set to allowed_values
            print('unable to set attr = [%s] by [%s]' % (k, v))

def get_attr_from_config(config):
    for k, v in config.items():
        #print('global {0}; {0}="{1}"'.format(k, v))
        try:
            exec('global {0}; {0}="{1}"'.format(k, str(v.decode('utf-8')).replace('.', ' '))) in globals(), locals()
        except:
            # bybass those value not valid, for example, string contain "."
            print('unable to assign attr = [%s] by [%s]' % (k, v))

    #print(globals())
    #print(locals())


def get_smart_scan_state_from_policy(dsapi):
    """ Gets the value of the firewall_setting_network_engine_mode property of a policy.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The id of the policy to get the firewall_setting_network_engine_mode value from.
    :return: A string with the firewall_setting_network_engine_mode value.
    """
    api = dsapi.api
    api_exception = dsapi.api_exception

    configuration = dsapi.configuration
    policy_id = dsapi.policy_id
    computer_id = dsapi.computer_id
    api_version = dsapi.default_api_version

    overrides = False

    #pprint(vars(configuration))

    try:
        # Get the policy details from Deep Security Manager
        api_instance = api.PoliciesApi(api.ApiClient(configuration))
        policy =  api_instance.describe_policy(policy_id=policy_id, api_version=api_version, overrides=overrides)
        #pprint(dir(policy))
        #pprint(vars(policy))
        return policy.policy_settings.anti_malware_setting_smart_scan_state.value

    except api_exception as e:
        return "Exception: " + str(e)

def set_smart_scan_state_from_policy(dsapi):
    """ Sets the value of the firewall_setting_network_engine_mode property of a policy.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The id of the policy to get the firewall_setting_network_engine_mode value from.
    :return: A SettingValue object that contains the modified value.
    """
    from deepsecurity import Policy
    from deepsecurity import PolicySettings
    from deepsecurity.models.setting_value import SettingValue

    api = dsapi.api
    api_exception = dsapi.api_exception

    configuration = dsapi.configuration
    policy_id = dsapi.policy_id
    computer_id = dsapi.computer_id
    api_version = dsapi.default_api_version

    computer_properties = dsapi.computer_properties
    value = computer_properties['policies'][0]['policySettings']['antiMalwareSettingSmartScanState']['value']
    print('value = ', value)


    # Create a SettingValue object and set the value to either "Inline" or "Tap"
    smart_scan_state = api.SettingValue()
    smart_scan_state.value = value
    PolicyValue = smart_scan_state
    PolicySetting = 'anti_malware_setting_smart_scan_state'

    policy = Policy(policy_settings=PolicySettings(anti_malware_setting_smart_scan_state=SettingValue(value)))

    try:
        # Modify the setting on Deep Security Manager
        api_instance = api.PoliciesApi(api.ApiClient(configuration))
        api_instance.modify_policy(policy_id, policy, api_version, overrides=False)
        return api_instance.modify_policy(policy_id, policy, api_version, overrides=False).policy_settings.anti_malware_setting_smart_scan_state.value

    except api_exception as e:
        return "Exception: " + str(e)

def get_smart_scan_state_from_computer(dsapi):
    """ Gets the value of the firewall_setting_network_engine_mode property of a policy.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The id of the policy to get the firewall_setting_network_engine_mode value from.
    :return: A string with the firewall_setting_network_engine_mode value.
    """
    overrides = False
    from deepsecurity.models.computer_settings import ComputerSettings
    from deepsecurity.models.setting_value import SettingValue
    #computer_settings = ComputerSettings()
    #value = SettingValue()
    api = dsapi.api
    api_exception = dsapi.api_exception

    configuration = dsapi.configuration
    policy_id = dsapi.policy_id
    computer_id = dsapi.computer_id
    api_version = dsapi.default_api_version

    try:
        # Get the policy details from Deep Security Manager
        api_instance = api.ComputersApi(api.ApiClient(configuration))
        computer =  api_instance.describe_computer(computer_id=computer_id, api_version=api_version, overrides=overrides)
        #pprint(dir(policy))
        #pprint(vars(policy))
        return computer.computer_settings.anti_malware_setting_smart_scan_state.value

    except api_exception as e:
        return "Exception: " + str(e)

def set_smart_scan_state_from_computer(dsapi):
    """ Sets the value of the firewall_setting_network_engine_mode property of a policy.

    :param api: The Deep Security API modules.
    :param configuration: Configuration object to pass to the api client.
    :param api_version: The version of the API to use.
    :param api_exception: The Deep Security API exception module.
    :param policy_id: The id of the policy to get the firewall_setting_network_engine_mode value from.
    :return: A SettingValue object that contains the modified value.
    """
    #from deepsecurity import Computer
    #from deepsecurity import ComputerSettings
    #from deepsecurity.models.setting_value import SettingValue

    # Create a SettingValue object and set the value to either "Inline" or "Tap"
    #smart_scan_state = api.SettingValue()
    #smart_scan_state.value = value
    #ComputerValue = smart_scan_state
    #ComputerSettings = 'anti_malware_setting_smart_scan_state'

    api = dsapi.api
    api_exception = dsapi.api_exception

    configuration = dsapi.configuration
    policy_id = dsapi.policy_id
    computer_id = dsapi.computer_id
    api_version = dsapi.default_api_version

    computer_properties = dsapi.computer_properties
    value = computer_properties['computers'][0]['computerSettings']['antiMalwareSettingSmartScanState']['value']
    print('value = ', value)

    overrides = False

    setting_value = api.SettingValue()
    setting_value.value = value
    computer_settings = api.ComputerSettings()
    computer_settings.anti_malware_setting_smart_scan_state = setting_value
    computer = api.Computer()
    computer.computer_settings = computer_settings

    #computer = api.Computer(computer_settings=api.ComputerSettings(anti_malware_setting_smart_scan_state=api.SettingValue(value)))

    try:
        # Modify the setting on Deep Security Manager
        api_instance = api.ComputersApi(api.ApiClient(configuration))
        api_instance.modify_computer(computer_id, computer, api_version, overrides=overrides)
        return api_instance.modify_computer(computer_id, computer, api_version, overrides=overrides).computer_settings.anti_malware_setting_smart_scan_state.value

    except api_exception as e:
        return "Exception: " + str(e)


def get_settings_from_policy(dsapi, computer_property_file='computer_properties.json'):
    api = dsapi.api
    api_exception = dsapi.api_exception

    configuration = dsapi.configuration
    policy_id = dsapi.policy_id
    computer_id = dsapi.computer_id
    api_version = dsapi.default_api_version

    with open(computer_property_file) as raw_properties:
        computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    computer = api.Computer()
    #computer.computer_settings = computer_settings
    overrides = False

    expand_options = api.Expand()
    expand_options.add(expand_options.all)
    expand = expand_options.list()

    try:
        api_instance = api.PoliciesApi(api.ApiClient(configuration))
        api_response = api_instance.describe_policy(policy_id=policy_id, api_version=api_version, overrides=overrides)
        #pprint(api_response)

        # write back to computer_properties
        computer_properties = dsapi.computer_properties
        for k, v in computer_properties['computers'][0]['policySettings'].items():
            for m, n in api_response.policy_settings.attribute_map.items():
                if api_response.policy_settings.attribute_map[m] == k:
                    value = getattr(api_response.policy_settings, m)
                    #print(k, v ,m, n, value)
                    computer_properties['computers'][0]['policySettings'][k]['value'] = value.value
                    break

        with open(computer_property_file, "w") as raw_properties:
            json.dump(computer_properties, raw_properties, indent=4, separators=(',', ':'), default=json_serial)

    except api_exception as e:
        print("An exception occurred when calling ComputersApi.modify_computer: %s\n" % e)

def set_settings_from_policy(dsapi, computer_property_file='computer_properties.json'):
    api = dsapi.api
    api_exception = dsapi.api_exception

    configuration = dsapi.configuration
    pprint(vars(configuration))
    policy_id = dsapi.policy_id
    computer_id = dsapi.computer_id
    api_version = dsapi.default_api_version

    with open(computer_property_file) as raw_properties:
        computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    for k, v in computer_properties['computers'][0]['computerSettings'].items():
        #print(k, v)
        setting_value = api.SettingValue()
        setting_value.value = v
        policy_settings = api.PolicySettings()
        for m, n in policy_settings.attribute_map.items():
            if policy_settings.attribute_map[m] == k:
                obj_key = m
                obj_val = v
                #print(k, v ,m, n, obj_key, obj_val)
                break
        #print(obj_key)
        setattr (policy_settings, obj_key, obj_val)

    policy = api.Policy()
    policy.policy_settings = policy_settings
    overrides = False

    try:
        api_instance = api.PoliciesApi(api.ApiClient(configuration))
        api_response = api_instance.modify_policy(policy_id=policy_id, policy=policy, api_version=api_version, overrides=overrides)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling ComputersApi.modify_computer: %s\n" % e)

def get_settings_from_computer(dsapi, computer_property_file='computer_properties.json'):
    api = dsapi.api
    api_exception = dsapi.api_exception

    configuration = dsapi.configuration
    policy_id = dsapi.policy_id
    computer_id = dsapi.computer_id
    api_version = dsapi.default_api_version

    with open(computer_property_file) as raw_properties:
        computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    computer = api.Computer()
    #computer.computer_settings = computer_settings
    overrides = False

    expand_options = api.Expand()
    expand_options.add(expand_options.all)
    expand = expand_options.list()

    try:
        api_instance = api.ComputersApi(api.ApiClient(configuration))
        api_response = api_instance.describe_computer(computer_id=computer_id, api_version=api_version, expand=expand, overrides=overrides)
        #pprint(api_response)

        # write back to computer_properties
        computer_properties = dsapi.computer_properties
        for k, v in computer_properties['computers'][0]['computerSettings'].items():
            for m, n in api_response.computer_settings.attribute_map.items():
                if api_response.computer_settings.attribute_map[m] == k:
                    value = getattr(api_response.computer_settings, m)
                    #print(k, v ,m, n, value)
                    computer_properties['computers'][0]['computerSettings'][k]['value'] = value.value
                    break

        with open(computer_property_file, "w") as raw_properties:
            json.dump(computer_properties, raw_properties, indent=4, separators=(',', ':'), default=json_serial)

    except api_exception as e:
        print("An exception occurred when calling ComputersApi.modify_computer: %s\n" % e)

def set_settings_from_computer(dsapi, computer_property_file='computer_properties.json'):
    api = dsapi.api
    api_exception = dsapi.api_exception

    configuration = dsapi.configuration
    policy_id = dsapi.policy_id
    computer_id = dsapi.computer_id
    api_version = dsapi.default_api_version

    with open(computer_property_file) as raw_properties:
        computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    for k, v in computer_properties['computers'][0]['computerSettings'].items():
        #print(k, v)
        setting_value = api.SettingValue()
        setting_value.value = v
        computer_settings = api.ComputerSettings()
        for m, n in computer_settings.attribute_map.items():
            if computer_settings.attribute_map[m] == k:
                obj_key = m
                obj_val = v
                print(k, v ,m, n, obj_key, obj_val)
                break
        #print(obj_key)
        setattr (computer_settings, obj_key, obj_val)

    computer = api.Computer()
    computer.computer_settings = computer_settings
    overrides = False

    try:
        api_instance = api.ComputersApi(api.ApiClient(configuration))
        api_response = api_instance.modify_computer(computer_id, computer, api_version, overrides=overrides)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling ComputersApi.modify_computer: %s\n" % e)


def get_schedule_from_dsm(dsapi, schedule_id=None):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    api_response = None
    api_instance = api.SchedulesApi(api.ApiClient(configuration))
    try:
        api_response = api_instance.describe_schedule(schedule_id=schedule_id, api_version=api_version)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling SchedulesApi.describe_schedule: %s\n" % e)

    return api_response

def search_schedules_from_dsm(dsapi, **search_filter):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    api_response = None
    api_instance = api.SchedulesApi(api.ApiClient(configuration))
    search_filter = api.SearchFilter(search_filter)
    try:
        api_response = api_instance.search_schedules(api_version=api_version, search_filter=search_filter)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling SchedulesApi.search_schedules: %s\n" % e)

    return api_response

def list_schedules_from_dsm(dsapi, computer_property_file=None, update=False):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    api_response = None
    api_instance = api.SchedulesApi(api.ApiClient(configuration))
    try:
        api_response = api_instance.list_schedules(api_version=api_version)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling SchedulesApi.list_schedules: %s\n" % e)

    # write back to computer_properties
    if computer_property_file and os.path.exists(computer_property_file):
        schedule = api.Schedule()
        name_map = schedule.attribute_map
        if not update:
            configs = api_response.to_dict()['schedules']
            new_config = list()
            for config in configs:
                new_config.append({name_map[name]: val for name, val in config.items()})
            computer_properties['schedules'] = new_config # to fullfill payload format
        else: # [keep property file] and update those items in dsm but not in property file
            all_name_in_dsm = set([x['name'].decode('utf-8') for x in api_response.to_dict()['schedules']])
            all_name_in_config = set([x['name'] for x in computer_properties['schedules']])
            update_set = (all_name_in_dsm - all_name_in_config)
            for dsm in api_response.to_dict()['schedules']:
                if dsm['name'] in update_set:
                    new_dsm = {name_map[name]: val for name, val in dsm.items()}
                    computer_properties['schedules'].append(new_dsm) # to fullfill payload format
        with open(computer_property_file, "w") as raw_properties:
            json.dump(computer_properties, raw_properties, indent=2, separators=(',', ':'), default=json_serial)

    return api_response

def update_or_create_schedules_to_dsm(dsapi, computer_property_file=None, delete=False):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    all_schedules = list_schedules_from_dsm(dsapi)

    all_name_in_dsm = set([x['name'].decode('utf-8') for x in all_schedules.to_dict()['schedules']])
    print(all_name_in_dsm)
    all_name_in_config = set([x['name'] for x in computer_properties['schedules']])
    print(all_name_in_config)
    #print(all_name_in_dsm & all_name_in_config)
    #print(all_name_in_dsm | all_name_in_config)
    #print(all_name_in_dsm - all_name_in_config)
    #print(all_name_in_config - all_name_in_dsm)
    for config in computer_properties['schedules']:
        schedule_id = config['ID']
        name = config['name']
        description = config['description']
        hours_of_week = config['hoursOfWeek']
        schedule = api.Schedule()
        schedule.name = name
        schedule.description = description
        schedule.hours_of_week = hours_of_week
        api_instance = api.SchedulesApi(api.ApiClient(configuration))
        for dsm in all_schedules.to_dict()['schedules']:
            if dsm['name'] == name:
                # modify_schedule
                schedule_id = dsm['id']
                print('modify_schedule for name = [%s]' % dsm['name'])
                try:
                    api_response = api_instance.modify_schedule(schedule_id=schedule_id, schedule=schedule, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling SchedulesApi.modify_schedule: %s\n" % e)

                break
        else:
            # create_schedule
            print('create_schedule for name = [%s]' % name)
            try:
                api_response = api_instance.create_schedule(schedule=schedule, api_version=api_version)
                #pprint(api_response)
            except api_exception as e:
                print("An exception occurred when calling SchedulesApi.create_schedule: %s\n" % e)

    if delete: # delete those items in dsm but not in property file, i.e. mirro from property file to dsm
        for dsm in all_schedules.to_dict()['schedules']:
            if dsm['name'] in (all_name_in_dsm - all_name_in_config):
                # delete_schedule
                print('delete_schedule for name = [%s]' % dsm['name'])
                schedule_id = dsm['id']
                try:
                    api_response = api_instance.delete_schedule(schedule_id=schedule_id, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling SchedulesApi.delete_schedule: %s\n" % e)

    return True


def get_file_list_from_dsm(dsapi, file_list_id=None):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    api_response = None
    api_instance = api.FileListsApi(api.ApiClient(configuration))
    try:
        api_response = api_instance.describe_file_list(file_list_id=file_list_id, api_version=api_version)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling FileListsApi.describe_file_list: %s\n" % e)

    return api_response

def search_file_lists_from_dsm(dsapi, **search_filter):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    api_response = None
    api_instance = api.FileListsApi(api.ApiClient(configuration))
    search_filter = api.SearchFilter(search_filter)
    try:
        api_response = api_instance.search_file_lists(api_version=api_version, search_filter=search_filter)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling FileListsApi.search_file_lists: %s\n" % e)

    return api_response

def list_file_lists_from_dsm(dsapi, computer_property_file=None, update=False):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    api_response = None
    api_instance = api.FileListsApi(api.ApiClient(configuration))
    try:
        api_response = api_instance.list_file_lists(api_version=api_version)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling FileListsApi.list_file_lists: %s\n" % e)

    # write back to computer_properties
    if computer_property_file and os.path.exists(computer_property_file):
        file_list = api.FileList()
        name_map = file_list.attribute_map
        if not update: # update those items in dsm but not in property file
            configs = api_response.to_dict()['file_lists'] # to fullfill payload format
            new_config = list()
            for config in configs:
                new_config.append({name_map[name]: val for name, val in config.items()})
            computer_properties['fileLists'] = new_config # to fullfill payload format
        else: # [keep property file] and update those items in dsm but not in property file
            all_name_in_dsm = set([x['name'].decode('utf-8') for x in api_response.to_dict()['file_lists']])
            all_name_in_config = set([x['name'] for x in computer_properties['fileLists']])
            update_set = (all_name_in_dsm - all_name_in_config)
            for dsm in api_response.to_dict()['file_lists']:
                if dsm['name'] in update_set:
                    new_dsm = {name_map[name]: val for name, val in dsm.items()}
                    computer_properties['fileLists'].append(new_dsm) # to fullfill payload format
        with open(computer_property_file, "w") as raw_properties:
            json.dump(computer_properties, raw_properties, indent=2, separators=(',', ':'), default=json_serial)

    return api_response

def update_or_create_file_lists_to_dsm(dsapi, computer_property_file=None, delete=False):

    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    all_file_lists = list_file_lists_from_dsm(dsapi)

    all_name_in_dsm = set([x['name'].decode('utf-8') for x in all_file_lists.to_dict()['file_lists']])
    all_name_in_config = set([x['name'] for x in computer_properties['fileLists']])

    for config in computer_properties['fileLists']:
        file_list_id = config['ID']
        name = config['name']
        description = config['description']
        items = config['items']
        file_list = api.FileList()
        file_list.name = name
        file_list.description = description
        file_list.items = items
        api_instance = api.FileListsApi(api.ApiClient(configuration))
        for dsm in all_file_lists.to_dict()['file_lists']:
            if dsm['name'] == name:
                # modify_file_list
                file_list_id = dsm['id']
                print('modify_file_list for name = [%s]' % dsm['name'])
                try:
                    api_response = api_instance.modify_file_list(file_list_id=file_list_id, file_list=file_list, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling FileListsApi.modify_file_list: %s\n" % e)

                break
        else:
            # create_file_list
            print('create_file_list for name = [%s]' % name)
            try:
                api_response = api_instance.create_file_list(file_list=file_list, api_version=api_version)
                #pprint(api_response)
            except api_exception as e:
                print("An exception occurred when calling FileListsApi.create_file_list: %s\n" % e)

    if delete: # delete those items in dsm but not in property file, i.e. mirro from property file to dsm
        for dsm in all_file_lists.to_dict()['file_lists']:
            if dsm['name'] in (all_name_in_dsm - all_name_in_config):
                # delete_file_list
                print('delete_file_list for name = [%s]' % dsm['name'])
                file_list_id = dsm['id']
                try:
                    api_response = api_instance.delete_file_list(file_list_id=file_list_id, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling FileListsApi.delete_file_list: %s\n" % e)

    return True


def get_file_extension_list_from_dsm(dsapi, file_extension_list_id=None):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    api_response = None
    api_instance = api.FileExtensionListsApi(api.ApiClient(configuration))
    try:
        api_response = api_instance.describe_file_extension_list(file_extension_list_id=file_extension_list_id, api_version=api_version)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling FileExtensionListsApi.describe_file_extension_list: %s\n" % e)

    return api_response

def search_file_extension_lists_from_dsm(dsapi, **search_filter):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    api_response = None
    api_instance = api.FileExtensionListsApi(api.ApiClient(configuration))
    search_filter = api.SearchFilter(search_filter)
    try:
        api_response = api_instance.search_file_extension_lists(api_version=api_version, search_filter=search_filter)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling FileExtensionListsApi.search_file_extension_lists: %s\n" % e)

    return api_response

def list_file_extension_lists_from_dsm(dsapi, computer_property_file=None, update=False):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    api_response = None
    api_instance = api.FileExtensionListsApi(api.ApiClient(configuration))
    try:
        api_response = api_instance.list_file_extension_lists(api_version=api_version)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling FileExtensionListsApi.list_file_extension_lists: %s\n" % e)

    # write back to computer_properties
    if computer_property_file and os.path.exists(computer_property_file):
        file_extension_list = api.FileExtensionList()
        name_map = file_extension_list.attribute_map
        if not update: # update those items in dsm but not in property file
            configs = api_response.to_dict()['file_extension_lists'] # to fullfill payload format
            new_config = list()
            for config in configs:
                new_config.append({name_map[name]: val for name, val in config.items()})
            computer_properties['antiMalwareConfigurations'] = new_config # to fullfill payload format
        else: # [keep property file] and update those items in dsm but not in property file
            all_name_in_dsm = set([x['name'].decode('utf-8') for x in api_response.to_dict()['file_extension_lists']])
            all_name_in_config = set([x['name'] for x in computer_properties['fileExtensionLists']])
            update_set = (all_name_in_dsm - all_name_in_config)
            for dsm in api_response.to_dict()['file_extension_lists']:
                if dsm['name'] in update_set:
                    new_dsm = {name_map[name]: val for name, val in dsm.items()}
                    computer_properties['fileExtensionLists'].append(new_dsm) # to fullfill payload format
        with open(computer_property_file, "w") as raw_properties:
            json.dump(computer_properties, raw_properties, indent=2, separators=(',', ':'), default=json_serial)

    return api_response

def update_or_create_file_extension_lists_to_dsm(dsapi, computer_property_file=None, delete=False):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    all_file_extension_lists = list_file_extension_lists_from_dsm(dsapi)

    all_name_in_dsm = set([x['name'].decode('utf-8') for x in all_file_extension_lists.to_dict()['file_extension_lists']])
    all_name_in_config = set([x['name'] for x in computer_properties['fileExtensionLists']])

    for config in computer_properties['fileExtensionLists']:
        file_extension_list_id = config['ID']
        name = config['name']
        description = config['description']
        items = config['items']
        file_extension_list = api.FileExtensionList()
        file_extension_list.name = name
        file_extension_list.description = description
        file_extension_list.items = items
        api_instance = api.FileExtensionListsApi(api.ApiClient(configuration))
        for dsm in all_file_extension_lists.to_dict()['file_extension_lists']:
            if dsm['name'] == name:
                # modify_file_extension_list
                file_extension_list_id = dsm['id']
                print('file_extension_list_id for name = [%s]' % dsm['name'])
                try:
                    api_response = api_instance.modify_file_extension_list(file_extension_list_id=file_extension_list_id, file_extension_list=file_extension_list, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling FileExtensionListsApi.modify_file_extension_list: %s\n" % e)

                break
        else:
            # create_file_extension_list
            print('create_file_extension_list for name = [%s]' % name)
            try:
                api_response = api_instance.create_file_extension_list(file_extension_list=file_extension_list, api_version=api_version)
                #pprint(api_response)
            except api_exception as e:
                print("An exception occurred when calling FileExtensionListsApi.create_file_extension_list: %s\n" % e)

    if delete: # delete those items in dsm but not in property file, i.e. mirro from property file to dsm
        for dsm in all_file_extension_lists.to_dict()['file_extension_lists']:
            if dsm['name'] in (all_name_in_dsm - all_name_in_config):
                # delete_file_extension_list
                print('delete_file_extension_list for name = [%s]' % dsm['name'])
                file_extension_list_id = dsm['id']
                try:
                    api_response = api_instance.delete_file_extension_list(file_extension_list_id=file_extension_list_id, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling FileExtensionListsApi.delete_file_extension_list: %s\n" % e)

    return True


def get_directory_list_from_dsm(dsapi, directory_list_id=None):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    api_response = None
    api_instance = api.DirectoryListsApi(api.ApiClient(configuration))
    try:
        api_response = api_instance.describe_directory_list(directory_list_id=directory_list_id, api_version=api_version)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling DirectoryListsApi.describe_directory_list: %s\n" % e)

    return api_response

def search_directory_lists_from_dsm(dsapi, **search_filter):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    api_response = None
    api_instance = api.DirectoryListsApi(api.ApiClient(configuration))
    search_filter = api.SearchFilter(search_filter)
    try:
        api_response = api_instance.search_directory_lists(api_version=api_version, search_filter=search_filter)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling DirectoryListsApi.search_directory_lists: %s\n" % e)

    return api_response

def list_directory_lists_from_dsm(dsapi, computer_property_file=None, update=False):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    api_response = None
    api_instance = api.DirectoryListsApi(api.ApiClient(configuration))
    try:
        api_response = api_instance.list_directory_lists(api_version=api_version)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling DirectoryListsApi.list_directory_lists: %s\n" % e)

    # write back to computer_properties
    if computer_property_file and os.path.exists(computer_property_file):
        directory_list = api.DirectoryList()
        name_map = directory_list.attribute_map
        if not update: # update those items in dsm but not in property file
            configs = api_response.to_dict()['directory_lists'] # to fullfill payload format
            new_config = list()
            for config in configs:
                new_config.append({name_map[name]: val for name, val in config.items()})
            computer_properties['directoryLists'] = new_config # to fullfill payload format
        else: # [keep property file] and update those items in dsm but not in property file
            all_name_in_dsm = set([x['name'].decode('utf-8') for x in api_response.to_dict()['directory_lists']])
            all_name_in_config = set([x['name'] for x in computer_properties['directoryLists']])
            update_set = (all_name_in_dsm - all_name_in_config)
            for dsm in api_response.to_dict()['directory_lists']:
                if dsm['name'] in update_set:
                    new_dsm = {name_map[name]: val for name, val in dsm.items()}
                    computer_properties['directoryLists'].append(new_dsm) # to fullfill payload format
        with open(computer_property_file, "w") as raw_properties:
            json.dump(computer_properties, raw_properties, indent=2, separators=(',', ':'), default=json_serial)

    return api_response

def update_or_create_directory_lists_to_dsm(dsapi, computer_property_file=None, delete=False):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    all_directory_lists = list_directory_lists_from_dsm(dsapi)

    all_name_in_dsm = set([x['name'].decode('utf-8') for x in all_directory_lists.to_dict()['directory_lists']])
    all_name_in_config = set([x['name'] for x in computer_properties['directoryLists']])

    for config in computer_properties['directoryLists']:
        directory_list_id = config['ID']
        name = config['name']
        description = config['description']
        items = config['items']
        directory_list = api.DirectoryList()
        directory_list.name = name
        directory_list.description = description
        directory_list.items = items
        api_instance = api.DirectoryListsApi(api.ApiClient(configuration))
        for dsm in all_directory_lists.to_dict()['directory_lists']:
            if dsm['name'] == name:
                # modify_directory_list
                directory_list_id = dsm['id']
                print('modify_directory_list for name = [%s]' % dsm['name'])
                try:
                    api_response = api_instance.modify_directory_list(directory_list_id=directory_list_id, directory_list=directory_list, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling DirectoryList.file_extension_list_id: %s\n" % e)

                break
        else:
            # create_directory_list
            print('create_directory_list for name = [%s]' % name)
            try:
                api_response = api_instance.create_directory_list(directory_list=directory_list, api_version=api_version)
                #pprint(api_response)
            except api_exception as e:
                print("An exception occurred when calling DirectoryList.create_directory_list: %s\n" % e)

    if delete: # delete those items in dsm but not in property file, i.e. mirro from property file to dsm
        for dsm in all_directory_lists.to_dict()['directory_lists']:
            if dsm['name'] in (all_name_in_dsm - all_name_in_config):
                # delete_directory_list
                print('delete_directory_list for name = [%s]' % dsm['name'])
                directory_list_id = dsm['id']
                try:
                    api_response = api_instance.delete_directory_list(directory_list_id=directory_list_id, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling DirectoryList.delete_directory_list: %s\n" % e)

    return True


def get_anti_malware_from_dsm(dsapi, anti_malware_id=None):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    api_response = None
    api_instance = api.AntiMalwareConfigurationsApi(api.ApiClient(configuration))
    try:
        api_response = api_instance.describe_anti_malware(anti_malware_id=anti_malware_id, api_version=api_version)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling AntiMalwareConfigurationsApi.describe_anti_malware: %s\n" % e)

    return api_response

def search_anti_malwares_from_dsm(dsapi, **search_filter):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    api_response = None
    api_instance = api.AntiMalwareConfigurationsApi(api.ApiClient(configuration))
    search_filter = api.SearchFilter(search_filter)
    try:
        api_response = api_instance.search_anti_malwares(api_version=api_version, search_filter=search_filter)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling AntiMalwareConfigurationsApi.search_anti_malwares: %s\n" % e)

    return api_response

def list_anti_malwares_from_dsm(dsapi, computer_property_file=None, update=False):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    api_response = None
    api_instance = api.AntiMalwareConfigurationsApi(api.ApiClient(configuration))
    try:
        api_response = api_instance.list_anti_malwares(api_version=api_version)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling AntiMalwareConfigurationsApi.list_anti_malwares: %s\n" % e)

    # write back to computer_properties
    if computer_property_file and os.path.exists(computer_property_file):
        anti_malware_configuration = api.AntiMalwareConfiguration()
        name_map = anti_malware_configuration.attribute_map
        if not update: # update those items in dsm but not in property file
            configs = api_response.to_dict()['anti_malware_configurations']
            new_config = list()
            for config in configs:
                new_config.append({name_map[name]: val for name, val in config.items()})
            computer_properties['antiMalwareConfigurations'] = new_config # to fullfill payload format
        else: # [keep property file] and update those items in dsm but not in property file
            all_name_in_dsm = set([x['name'].decode('utf-8') for x in api_response.to_dict()['anti_malware_configurations']])
            all_name_in_config = set([x['name'] for x in computer_properties['antiMalwareConfigurations']])
            update_set = (all_name_in_dsm - all_name_in_config)
            for dsm in api_response.to_dict()['anti_malware_configurations']:
                if dsm['name'] in update_set:
                    new_dsm = {name_map[name]: val for name, val in dsm.items()}
                    computer_properties['antiMalwareConfigurations'].append(new_dsm) # to fullfill payload format
        with open(computer_property_file, "w") as raw_properties:
            json.dump(computer_properties, raw_properties, indent=2, separators=(',', ':'), default=json_serial)

    return api_response

def update_or_create_anti_malware_to_dsm(dsapi, computer_property_file=None, delete=False):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    all_anti_malware_configurations = list_anti_malwares_from_dsm(dsapi)

    all_name_in_dsm = set([x['name'].decode('utf-8') for x in all_anti_malware_configurations.to_dict()['anti_malware_configurations']])
    all_name_in_config = set([x['name'] for x in computer_properties['antiMalwareConfigurations']])

    for config in computer_properties['antiMalwareConfigurations']:
        get_attr_from_config(config)
        anti_malware_configuration = api.AntiMalwareConfiguration()
        setattr_from_attribute_map(anti_malware_configuration, 'attribute_map')

        for k, v in anti_malware_configuration.to_dict().items():
            print(k, v)

        api_instance = api.AntiMalwareConfigurationsApi(api.ApiClient(configuration))
        for dsm in all_anti_malware_configurations.to_dict()['anti_malware_configurations']:
            if dsm['name'] == name:
                # modify_anti_malware
                anti_malware_id = dsm['id']
                print('modify_anti_malware for name = [%s]' % dsm['name'])
                try:
                    api_response = api_instance.modify_anti_malware(anti_malware_id=anti_malware_id , anti_malware_configuration=anti_malware_configuration, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling AntiMalwareConfigurationsApi.modify_anti_malware: %s\n" % e)

                break
        else:
            # create_anti_malware
            print('create_anti_malware for name = [%s]' % name)
            try:
                api_response = api_instance.create_anti_malware(anti_malware_configuration=anti_malware_configuration, api_version=api_version)
                #pprint(api_response)
            except api_exception as e:
                print("An exception occurred when calling AntiMalwareConfigurationsApi.create_anti_malware: %s\n" % e)

    if delete: # delete those items in dsm but not in property file, i.e. mirro from property file to dsm
        for dsm in all_anti_malware_configurations.to_dict()['anti_malware_configurations']:
            if dsm['name'] in (all_name_in_dsm - all_name_in_config):
                # delete_anti_malware
                anti_malware_id = dsm['id']
                try:
                    api_response = api_instance.delete_anti_malware(anti_malware_id=anti_malware_id, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling AntiMalwareConfigurationsApi.delete_anti_malware: %s\n" % e)

    return True


def get_policy_from_dsm(dsapi, policy_id=None):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    api_response = None
    api_instance = api.PoliciesApi(api.ApiClient(configuration))
    try:
        api_response = api_instance.describe_policy(policy_id=policy_id, api_version=api_version)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling PoliciesApi.describe_policy: %s\n" % e)

    return api_response

def search_policies_from_dsm(dsapi, **search_filter):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    api_response = None
    api_instance = api.PoliciesApi(api.ApiClient(configuration))
    search_filter = api.SearchFilter(search_filter)
    try:
        api_response = api_instance.search_policies (api_version=api_version, search_filter=search_filter)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling PoliciesApi.search_policies : %s\n" % e)

    return api_response

def list_policies_from_dsm(dsapi, computer_property_file=None, update=False):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    api_response = None
    api_instance = api.PoliciesApi(api.ApiClient(configuration))
    try:
        api_response = api_instance.list_policies(api_version=api_version)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling PoliciesApi.list_policies: %s\n" % e)

    # write back to computer_properties
    if computer_property_file and os.path.exists(computer_property_file):
        if not update: # update those items in dsm but not in property file
            result = serializ(api_response)
            #pprint(result)
            computer_properties['policies'] = result['policies'] # to fullfill payload format
        else: # [keep property file] and update those items in dsm but not in property file
            all_name_in_dsm = set([x['name'].decode('utf-8') for x in api_response.to_dict()['policies']])
            all_name_in_config = set([x['name'] for x in computer_properties['policies']])
            update_set = (all_name_in_dsm - all_name_in_config)
            for dsm in api_response.to_dict()['policies']:
                if dsm['name'] in update_set:
                    #new_dsm = {name_map[name]: val for name, val in dsm.items()}
                    new_dsm = serializ(api_response.policies(host_name=dsm['host_name']))
                    computer_properties['policies'].append(new_dsm) # to fullfill payload format
        with open(computer_property_file, "w") as raw_properties:
            json.dump(computer_properties, raw_properties, indent=2, separators=(',', ':'), default=json_serial)

    return api_response

def update_or_create_policy_to_dsm(dsapi, computer_property_file=None, delete=False):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    all_policies = list_policies_from_dsm(dsapi)

    all_name_in_dsm = set([x['name'].decode('utf-8') for x in all_policies.to_dict()['policies']])
    all_name_in_config = set([x['name'] for x in computer_properties['policies']])

    for config in computer_properties['policies']:
        get_attr_from_config(config)
        policy = api.Policy()
        setattr_from_attribute_map(policy, 'attribute_map')

        for k, v in policy.to_dict().items():
            print(k, v)

        api_instance = api.PoliciesApi(api.ApiClient(configuration))
        for dsm in all_policies.to_dict()['policies']:
            if dsm['name'] == name:
                # modify_policy
                policy_id = dsm['id']
                print('modify_policy for name = [%s]' % dsm['name'])
                try:
                    api_response = api_instance.modify_policy(policy_id=policy_id, policy=policy, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling PoliciesApi.modify_policy: %s\n" % e)

                break
        else:
            # create_policy
            print('create_anti_malware for name = [%s]' % name)
            try:
                api_response = api_instance.create_policy(policy=policy, api_version=api_version)
                #pprint(api_response)
            except api_exception as e:
                print("An exception occurred when calling PoliciesApi.create_policy: %s\n" % e)

    if delete: # delete those items in dsm but not in property file, i.e. mirro from property file to dsm
        for dsm in all_policies.to_dict()['policies']:
            if dsm['name'] in (all_name_in_dsm - all_name_in_config):
                # delete_policy
                policy_id = dsm['id']
                try:
                    api_response = api_instance.delete_policy(policy_id=policy_id, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling PoliciesApi.delete_policy: %s\n" % e)

    return True


def get_computer_from_dsm(dsapi, computer_id=None):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    api_response = None
    api_instance = api.ComputersApi(api.ApiClient(configuration))
    try:
        api_response = api_instance.describe_computer(computer_id=computer_id, api_version=api_version)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling ComputersApi.describe_computer: %s\n" % e)

    return api_response

def search_computers_from_dsm(dsapi, **search_filter):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    api_response = None
    api_instance = api.ComputersApi(api.ApiClient(configuration))
    search_filter = api.SearchFilter(search_filter)
    try:
        api_response = api_instance.search_computers(api_version=api_version, search_filter=search_filter)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling ComputersApi.search_computers: %s\n" % e)

    return api_response

def list_computers_from_dsm(dsapi, computer_property_file=None, update=False):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    api_response = None
    api_instance = api.ComputersApi(api.ApiClient(configuration))
    try:
        api_response = api_instance.list_computers(api_version=api_version)
        #pprint(api_response)
    except api_exception as e:
        print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)

    # write back to computer_properties
    if computer_property_file and os.path.exists(computer_property_file):
        if not update: # update those items in dsm but not in property file
            result = serializ(api_response)
            #pprint(result)
            computer_properties['computers'] = result['computers'] # to fullfill payload format
        else: # [keep property file] and update those items in dsm but not in property file
            all_name_in_dsm = set([x['host_name'].decode('utf-8') for x in api_response.to_dict()['computers']])
            all_name_in_config = set([x['hostName'] for x in computer_properties['computers']])
            update_set = (all_name_in_dsm - all_name_in_config)
            for dsm in api_response.to_dict()['computers']:
                if dsm['host_name'] in update_set:
                    #new_dsm = {name_map[name]: val for name, val in dsm.items()}
                    new_dsm = serializ(api_response.computers(host_name=dsm['host_name']))
                    computer_properties['computers'].append(new_dsm) # to fullfill payload format
        with open(computer_property_file, "w") as raw_properties:
            json.dump(computer_properties, raw_properties, indent=2, separators=(',', ':'), default=json_serial)

    return api_response

def update_or_create_computer_to_dsm(dsapi, computer_property_file=None, delete=False):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    all_computers = list_computers_from_dsm(dsapi)

    all_name_in_dsm = set([x['host_name'].decode('utf-8') for x in all_computers.to_dict()['computers']])
    all_name_in_config = set([x['hostName'] for x in computer_properties['computers']])

    for config in computer_properties['computers']:
        get_attr_from_config(config)
        computer = api.Computer()
        setattr_from_attribute_map(computer, 'attribute_map')

        for k, v in computer.to_dict().items():
            print(k, v)

        api_instance = api.ComputersApi(api.ApiClient(configuration))
        for dsm in all_computers.to_dict()['computers']:
            if dsm['host_name'] == hostName:
                # modify_computer
                computer_id = dsm['id']
                print('modify_computer for hostName = [%s]' % dsm['host_name'])
                try:
                    api_response = api_instance.modify_computer(computer_id=computer_id, computer=computer, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling ComputersApi.modify_computer: %s\n" % e)

                break
        else:
            # create_computer
            print('create_computer for hostName = [%s]' % hostName)
            try:
                api_response = api_instance.create_computer(computer=computer, api_version=api_version)
                #pprint(api_response)
            except api_exception as e:
                print("An exception occurred when calling ComputersApi.create_computer: %s\n" % e)

    if delete: # delete those items in dsm but not in property file, i.e. mirro from property file to dsm
        for dsm in all_computers.to_dict()['computers']:
            if dsm['host_name'] in (all_name_in_dsm - all_name_in_config):
                # delete_computer
                anti_malware_id = dsm['id']
                try:
                    api_response = api_instance.delete_computer(computer_id=computer_id, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling ComputersApi.delete_computer: %s\n" % e)

    return True


def update_or_create_policy_to_dsm2(dsapi, computer_property_file=None, delete=False):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    all_policies = list_policies_from_dsm(dsapi)

    all_name_in_dsm = set([x['name'].decode('utf-8') for x in all_policies.to_dict()['policies']])
    all_name_in_config = set([x['name'] for x in computer_properties['policies']])
    policies = deserialize_from_object(computer_properties['policies'], 'Policies')
    for config in computer_properties['policies']:
        name = config['name']
        print(name)
        policy = deserialize_from_object(config, 'Policy')
        #pprint(policy)
        api_instance = api.PoliciesApi(api.ApiClient(configuration))
        for dsm in all_policies.to_dict()['policies']:
            if dsm['name'] == name:
                # modify_policy
                policy_id = dsm['id']
                print('modify_policy for name = [%s]' % dsm['name'])
                try:
                    api_response = api_instance.modify_policy(policy_id=policy_id, policy=policy, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling PoliciesApi.modify_policy: %s\n" % e)

                break
        else:
            # create_policy
            print('create_policy for name = [%s]' % name)
            pprint(policy)
            try:
                api_response = api_instance.create_policy(policy=policy, api_version=api_version)
                #pprint(api_response)
            except api_exception as e:
                print("An exception occurred when calling PoliciesApi.create_policy: %s\n" % e)

    if delete: # delete those items in dsm but not in property file, i.e. mirro from property file to dsm
        for dsm in all_policies.to_dict()['policies']:
            if dsm['name'] in (all_name_in_dsm - all_name_in_config):
                # delete_policy
                policy_id = dsm['id']
                try:
                    api_response = api_instance.delete_policy(policy_id=policy_id, api_version=api_version)
                    #pprint(api_response)
                except api_exception as e:
                    print("An exception occurred when calling PoliciesApi.delete_policy: %s\n" % e)

    return api_response


def json_update_value_by_key(json, k, v):
    if isinstance(json, dict):
        for key in json.keys():
            if key == k:
                json[k] = v
            elif isinstance(json[key], dict):
                json_update_key_name(json[key], k, v)
            elif isinstance(json[key], list):
                for item in json[key]:
                    json_update_key_name(item, k, v)
    elif isinstance(json, list):
        for item in json:
            json_update_key_name(item, k, v)

    return json

def json_update_value_by_new_key_if_needed(json, k, v1, v2):
    if isinstance(json, dict):
        for key in json.keys():
            if key == k:
                if json[k] == v1:
                    json[k] = v2
            elif isinstance(json[key], dict):
                json_update_value_by_new_key_if_needed(json[key], k, v1, v2)
            elif isinstance(json[key], list):
                for item in json[key]:
                    json_update_value_by_new_key_if_needed(item, k, v1, v2)
    elif isinstance(json, list):
        for item in json:
            json_update_value_by_new_key_if_needed(item, k, v1, v2)

    return json

def json_update_key_name(json, k, new_key):
    if isinstance(json, dict):
        for key in json.keys():
            if key == k:
                json[new_key] = json.pop(key)
            elif isinstance(json[key], dict):
                json_update_key_name(json[key], k, new_key)
            elif isinstance(json[key], list):
                for item in json[key]:
                    json_update_key_name(item, k, new_key)
    elif isinstance(json, list):
        for item in json:
            json_update_key_name(item, k, new_key)

    return json

def extrat_element_from_json(obj, path):
    '''
    Extracts an element from a nested dictionary or
    a list of nested dictionaries along a specified path.
    If the input is a dictionary, a list is returned.
    If the input is a list of dictionary, a list of lists is returned.
    obj - list or dict - input dictionary or list of dictionaries
    path - list - list of strings that form the path to the desired element
    '''
    def extract(obj, path, ind, arr):
        '''
            Extracts an element from a nested dictionary
            along a specified path and returns a list.
            obj - dict - input dictionary
            path - list - list of strings that form the JSON path
            ind - int - starting index
            arr - list - output list
        '''
        key = path[ind]
        if ind + 1 < len(path):
            if isinstance(obj, dict):
                if key in obj.keys():
                    extract(obj.get(key), path, ind + 1, arr)
                else:
                    arr.append(None)
            elif isinstance(obj, list):
                if not obj:
                    arr.append(None)
                else:
                    for item in obj:
                        extract(item, path, ind, arr)
            else:
                arr.append(None)
        if ind + 1 == len(path):
            if isinstance(obj, list):
                if not obj:
                    arr.append(None)
                else:
                    for item in obj:
                        arr.append(item.get(key, None))
            elif isinstance(obj, dict):
                arr.append(obj.get(key, None))
            else:
                arr.append(None)
        return arr

    if isinstance(obj, dict):
        return extract(obj, path, 0, [])
    elif isinstance(obj, list):
        outer_arr = []
        for item in obj:
            outer_arr.append(extract(item, path, 0, []))
        return outer_arr



def policies_generation(dsapi, computer_property_file=None):
    api = dsapi.api
    api_exception = dsapi.api_exception
    api_version = dsapi.default_api_version
    configuration = dsapi.configuration

    MAX_RETRIES = 12

    computer_properties = None
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file) as raw_properties:
            computer_properties = json.load(raw_properties)
    computer_properties = computer_properties or dsapi.computer_properties

    computer_properties = json_update_key_name(computer_properties, 'ID', 'id')

    for ds_obj in obj_order: # fix order by using list data structure
        key = ds_obj
        value = objs_to_obj_klass[key]
        if key in computer_properties.keys():
            print('key = [%s] value = [%s]' % (key, value))
            #objs = deserialize_from_object(computer_properties[key], value)
            for ind, item in enumerate(computer_properties[key]):
                #print(type(item))
                #pprint(item)
                obj_id = item['id']
                obj_name = item['name']
                print('id   in properties = [%s]' % obj_id)
                print('name in properties = [%s]' % obj_name)
                obj = deserialize_from_object(item, value)
                api_instance_name = '{klass}Api'.format(klass=objs_to_objs_klass[key])
                #api_instance = api.SchedulesApi(api.ApiClient(configuration))
                api_instance = getattr(api, api_instance_name)(api.ApiClient(configuration))
                for i in range(1, MAX_RETRIES+1):
                    try:
                        api_name = 'create_{api}'.format(api=objs_to_obj_method[key])
                        api_response = getattr(api_instance, api_name)(obj, api_version=api_version)
                        #api_response = api_instance.create_schedule(schedule=schedule, api_version=api_version)
                    except api_exception as e:
                        if e.status == 429:
                            # Calculate sleep time
                            exp_backoff = (2 ** (i + 3)) / 1000
                            print('API rate limit is exceeded. Retry in {} s.'.format(exp_backoff))
                            time.sleep(exp_backoff)
                        elif e.status == 400:
                            # something already exists, trying to modify one instead of create one.
                            #print(e)
                            if 'already exists.' in e.body:
                                print('{}\n{}'.format(e.body, 'Trying to modify it'))
                                try:
                                    api_name = 'search_{api}'.format(api=objs_to_objs_method[key])
                                    search_criteria = api.SearchCriteria()
                                    search_criteria.field_name = "name"
                                    search_criteria.string_test = "equal"
                                    search_criteria.string_value = obj_name
                                    search_filter = api.SearchFilter(None, [search_criteria])
                                    search_filter.max_items = 1
                                    api_response = getattr(api_instance, api_name)(api_version=api_version, search_filter=search_filter)
                                    act_obj_id = getattr(api_response, objs_to_objs_properties[key])[0].id
                                    api_name = 'modify_{api}'.format(api=objs_to_obj_method[key])
                                    api_response = getattr(api_instance, api_name)(act_obj_id, obj, api_version=api_version)
                                except:
                                    print(e)

                            else:
                                print(e)
                                # TODO
                                return False
                        else:
                            print(e)
                            # TODO
                            return False

                    new_obj_id = api_response.to_dict()['id']
                    print('new id = [%s]' % new_obj_id)
                    computer_properties[key][ind]['id'] = new_obj_id

                    if key in obj_to_id_map.keys():
                        for item in obj_to_id_map[key]:
                            json_update_value_by_new_key_if_needed(computer_properties, item, obj_id, new_obj_id)

                    break

    # update 'id' back to computer_properties
    if computer_property_file and os.path.exists(computer_property_file):
        with open(computer_property_file, "w") as raw_properties:
            json.dump(computer_properties, raw_properties, indent=4, separators=(',', ':'), default=json_serial)

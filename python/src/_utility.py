from __future__ import absolute_import
from pprint import pprint
import six
import json
import datetime
import os
from argparse import Namespace
from itertools import islice

import datetime
import json
import mimetypes
from multiprocessing.pool import ThreadPool
import os
import re
import tempfile

# python 2 and python 3 compatibility library
import six
from six.moves.urllib.parse import quote

from deepsecurity.configuration import Configuration
import deepsecurity.models
from deepsecurity import rest


def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, (datetime.datetime, datetime.date)):
        return obj.isoformat()
    raise TypeError ("Type %s not serializable" % type(obj))

def merge_dicts(*dict_args):
    """
    Given any number of dicts, shallow copy and merge into a new dict,
    precedence goes to key value pairs in latter dicts.
    """
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result

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

def setattr_from_attribute_map(object, attribute_map):
    for k, v in getattr(object, attribute_map).items():
        #print(k, v)
        try:
            setattr(object, k, eval(v))
            #print('[%s] = %s ' % (k, eval(v)))
        except:
            # bybass those attribute not set to allowed_values
            print('unable to set attr = [%s] by [%s]' % (k, v))
    
def serializ(obj):
    result = {}
    attribute_map = obj.attribute_map
    swagger_types = obj.swagger_types
    for attr, _ in six.iteritems(swagger_types):
        new_attr = attribute_map[attr]
        value = getattr(obj, attr)
        if value in ['int', 'str', 'bool']:
            result[new_attr] = value
        else:
            if isinstance(value, list):
                #print('is list')
                result[new_attr] = list(map(
                    lambda x: get_attr_from_config(x) if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                #print('is obj')
                result[new_attr] = get_attr_from_config(value)
            elif isinstance(value, dict):
                #print('is dict') 
                result[new_attr] = dict(map(
                    lambda item: (item[0], get_attr_from_config(item[1]))
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[new_attr] = value

    return result

def deserialize2(obj):
    result = {}
    attribute_map = obj.attribute_map
    swagger_types = obj.swagger_types
    for attr, _ in six.iteritems(swagger_types):
        new_attr = attribute_map[attr]
        value = getattr(obj, attr)
        if value in ['int', 'str', 'bool']:
            result[new_attr] = value
        else:
            if isinstance(value, list):
                #print('is list')
                result[new_attr] = list(map(
                    lambda x: get_attr_from_config(x) if hasattr(x, "to_dict") else x,
                    value
                ))
            elif hasattr(value, "to_dict"):
                #print('is obj')
                result[new_attr] = get_attr_from_config(value)
            elif isinstance(value, dict):
                #print('is dict')
                result[new_attr] = dict(map(
                    lambda item: (item[0], get_attr_from_config(item[1]))
                    if hasattr(item[1], "to_dict") else item,
                    value.items()
                ))
            else:
                result[new_attr] = value

    return result

def deserialize_from_response(data, klass):
    """Deserializes response into an object.

    :param response: RESTResponse object to be deserialized.
    :param response_type: class literal for
        deserialized object, or string of class name.

    :return: deserialized object.
    """
    # handle file downloading
    # save response body into a tmp file and return the instance
    if klass == "file":
        return deserialize_file_(data)

    # fetch data from response object
    try:
        data = json.loads(data)
    except ValueError:
        data = data

    return deserialize_from_object(data, klass)

def deserialize_from_object(data, klass):
        """Deserializes dict, list, str into an object.

        :param data: dict, list or str.
        :param klass: class literal, or string of class name.

        :return: object.
        """
        PRIMITIVE_TYPES = (float, bool, bytes, six.text_type) + six.integer_types
        NATIVE_TYPES_MAPPING = {
            'int': int,
            'long': int if six.PY3 else long,  # noqa: F821
            'float': float,
            'str': str,
            'bool': bool,
            'date': datetime.date,
            'datetime': datetime.datetime,
            'object': object,
        }

        if data is None:
            return None

        if type(klass) == str:
            if klass.startswith('list['):
                sub_kls = re.match('list\[(.*)\]', klass).group(1)
                return [deserialize_from_object(sub_data, sub_kls)
                        for sub_data in data]

            if klass.startswith('dict('):
                sub_kls = re.match('dict\(([^,]*), (.*)\)', klass).group(2)
                return {k: deserialize_from_object(v, sub_kls)
                        for k, v in six.iteritems(data)}

            # convert str to class
            if klass in NATIVE_TYPES_MAPPING:
                klass = NATIVE_TYPES_MAPPING[klass]
            else:
                klass = getattr(deepsecurity.models, klass)

        if klass in PRIMITIVE_TYPES:
            return deserialize_primitive_(data, klass)
        elif klass == object:
            return deserialize_object_(data)
        elif klass == datetime.date:
            return deserialize_date_(data)
        elif klass == datetime.datetime:
            return deserialize_datatime_(data)
        else:
            return deserialize_model_(data, klass)

def deserialize_file_(response):
    """Deserializes body to file

    Saves response body into a file in a temporary folder,
    using the filename from the `Content-Disposition` header if provided.

    :param response:  RESTResponse.
    :return: file path.
    """
    fd, path = tempfile.mkstemp(dir=os.getcwd())
    os.close(fd)
    os.remove(path)

    content_disposition = response.getheader("Content-Disposition")
    if content_disposition:
        filename = re.search(r'filename=[\'"]?([^\'"\s]+)[\'"]?',
                                content_disposition).group(1)
        path = os.path.join(os.path.dirname(path), filename)

    with open(path, "wb") as f:
        f.write(response.data)

    return path

def deserialize_primitive_(data, klass):
    """Deserializes string to primitive type.

    :param data: str.
    :param klass: class literal.

    :return: int, long, float, str, bool.
    """
    try:
        return klass(data)
    except UnicodeEncodeError:
        return six.text_type(data)
    except TypeError:
        return data

def deserialize_object_(value):
    """Return a original value.

    :return: object.
    """
    return value

def deserialize_date_(string):
    """Deserializes string to date.

    :param string: str.
    :return: date.
    """
    try:
        from dateutil.parser import parse
        return parse(string).date()
    except ImportError:
        return string
    except ValueError:
        raise rest.ApiException(
            status=0,
            reason="Failed to parse `{0}` as date object".format(string)
        )

def deserialize_datatime_(string):
    """Deserializes string to datetime.

    The string should be in iso8601 datetime format.

    :param string: str.
    :return: datetime.
    """
    try:
        from dateutil.parser import parse
        return parse(string)
    except ImportError:
        return string
    except ValueError:
        raise rest.ApiException(
            status=0,
            reason=(
                "Failed to parse `{0}` as datetime object"
                .format(string)
            )
        )

def deserialize_model_(data, klass):
    """Deserializes list or dict to model.

    :param data: dict, list.
    :param klass: class literal.
    :return: model object.
    """

    if not klass.swagger_types and not hasattr(klass, 'get_real_child_model'):
        return data

    kwargs = {}
    if klass.swagger_types is not None:
        for attr, attr_type in six.iteritems(klass.swagger_types):
            #print(attr, attr_type, klass.attribute_map[attr])
            #print(type(data))
            if (data is not None):
                if klass.attribute_map[attr] in data:
                    if isinstance(data, (list, dict)):
                        value = data[klass.attribute_map[attr]]
                        #print(value, attr_type)
                        kwargs[attr] = deserialize_from_object(value, attr_type)
                        #pprint(kwargs)

    try:
        instance = klass(**kwargs)
    except:
        print('kwargs \n')
        #print(json.load(kwargs, indent=4))
        #print(json.dumps(kwargs, indent=4, sort_keys=True))
        pprint(kwargs)
        print('type of klass \n')
        print(type(klass))
        print('klass \n')
        pprint(klass)
        pass
        '''
        for a in kwargs.keys():
            try:
                print(getattr(klass, a))
                print(getattr(getattr(klass, a), 'allowed_values')[0])
                setattr(klass, a, getattr(getattr(klass, a), 'allowed_values')[0])
                print('pass try for %s' % a)
            except:
                print('except for %s' % a)
                pass
        instance = klass(**kwargs)
        '''

    #pprint(instance)
    if (isinstance(instance, dict) and
            klass.swagger_types is not None and
            isinstance(data, dict)):
        for key, value in data.items():
            if key not in klass.swagger_types:
                instance[key] = value
    if hasattr(instance, 'get_real_child_model'):
        print('get_real_child_model')
        klass_name = instance.get_real_child_model(data)
        if klass_name:
            instance = deserialize_from_object(data, klass_name)

    return instance

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

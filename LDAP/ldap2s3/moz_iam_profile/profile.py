#!/usr/bin/env python

import json
import jsonschema
import os
import time

class DotDict(dict):
    """
    Convert a dict to a fake class/object with attributes, such as:
    test = dict({"test": {"value": 1}})
    test.test.value = 2
    """
    def __init__(self, *args, **kwargs):
        dict.__init__(self, *args, **kwargs)
        try:
            #Python2
            for k, v in self.iteritems():
                self.__setitem__(k, v)
        except AttributeError:
            #Python3
            for k, v in self.items():
                self.__setitem__(k, v)

    def __getattr__(self, k):
        try:
            return dict.__getitem__(self, k)
        except KeyError:
             raise AttributeError( "'DotDict' object has no attribute '" + str(k) + "'")

    def __setitem__(self, k, v):
         dict.__setitem__(self, k, DotDict.__convert(v))

    __setattr__ = __setitem__

    def __delattr__(self, k):
        try:
            dict.__delitem__(self, k)
        except KeyError:
            raise AttributeError("'DotDict'  object has no attribute '" + str(k) + "'")

    @staticmethod
    def __convert(o):
        """
        Recursively convert `dict` objects in `dict`, `list`, `set`, and
        `tuple` objects to `DotDict` objects.
        """
        if isinstance(o, dict):
            o = DotDict(o)
        elif isinstance(o, list):
            o = list(DotDict.__convert(v) for v in o)
        elif isinstance(o, set):
            o = set(DotDict.__convert(v) for v in o)
        elif isinstance(o, tuple):
            o = tuple(DotDict.__convert(v) for v in o)
        return o


class User(object):
    """
    A Mozilla IAM Profile "v2" user structure.
    It is loaded a configuration file (JSON) and dynamically generated.
    If you wish to change the structure, modify the JSON file!

    By default this will load the JSON file with its defaults.

    You can use this like a normal class:
    ```
    from moz_iam_profile import User
    skel_user = User(user_id="bobsmith")
    skel_user.user_id.value = "notbobsmith"
    if skel_user.validate():
        profile = skel_user.as_json()
    ```
    """

    def __init__(self, user_structure_json_path='user_profile_core_plus_extended.json', **kwargs):
        # load default structure
        self.__dict__.update(self.load(user_structure_json_path))

        # Insert defaults from kwargs
        for kw in kwargs:
            if kw in self.__dict__.keys():
                try:
                    self.__dict__[kw]['value'] = kwargs[kw]
                except KeyError:
                    self.__dict__[kw]['values'] += [kwargs[kw]]
            else:
                raise Exception('Unknown user profile attribute {}'.format(kw))

        self.initialize_timestamps()

    def load(self, user_structure_json_path):
        """
        Load the json structure into a 'DotDict' so that attributes appear as addressable object values
        """
        if not os.path.isfile(user_structure_json_path):
            dirname = os.path.dirname(os.path.realpath(__file__))
            path = dirname+'/'+user_structure_json_path
        else:
            path = user_structure_json_path
        return DotDict(json.load(open(path)))

    def initialize_timestamps(self):
        #instruct libc that we want UTC
        os.environ['TZ'] = 'UTC'

        now = time.strftime('%Y-%m-%dT%H:%M:%S.000Z')

        for item in self.__dict__:
            if type(self.__dict__[item]) is not DotDict: continue
            try:
                self.__dict__[item]['metadata']['created'] = now
                self.__dict__[item]['metadata']['last_modified'] = now
            except KeyError:
                # This is a 2nd level attribute such as `access_information`
                # Note that we do not have a 3rd level so this is sufficient
                for subitem in self.__dict__[item]:
                    self.__dict__[item][subitem]['metadata']['created'] = now
                    self.__dict__[item][subitem]['metadata']['last_modified'] = now
        # XXX Hard-coded special profile value
        self.__dict__['last_modified'].value = now

    def as_json(self):
        """
        Outputs a JSON version of this user
        """

        return json.dumps(self.__dict__)

    def as_dict(self):
        """
        Outputs a real dict version of this user (not a DotDict)
        """
        return dict(self.__dict__)

    def validate(self, schema_file="profile.schema"):
        """
        Validates against a JSON schema
        """
        if not os.path.isfile(schema_file):
            dirname = os.path.dirname(os.path.realpath(__file__))
            path = dirname+'/'+schema_file
        else:
            path = schema_file

        return jsonschema.validate(self.as_dict(), json.load(open(path)))

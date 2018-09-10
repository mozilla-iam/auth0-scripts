#!/usr/bin/env python

class DotDict(dict):
    """
    Convert a dict to a class/object with attributes, such as:
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



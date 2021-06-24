from itertools import chain
from future.utils import iteritems, with_metaclass
import os

GLOBAL_OPTS = {}


class Option(object):
    """ Exploit attribute that is set by the end user """

    def __init__(self, default, description=""):
        self.label = None
        self.description = description

        if default:
            self.__set__("", default)
        else:
            self.display_value = ""
            self.value = ""

    def __get__(self, instance, owner):
        return self.value


class OptString(Option):
    """ Option String attribute """

    def __set__(self, instance, value):
        try:
            self.value = self.display_value = str(value)
        except ValueError:
            raise ValueError("Invalid option. Cannot cast '{}' to string.".format(value))


class BaseModuleAggregator(type):
    def __new__(cls, name, bases, attrs):
        try:
            base_module_attributes = chain([base.module_attributes for base in bases])
        except AttributeError:
            attrs["module_attributes"] = {}
        else:
            attrs["module_attributes"] = {k: v for d in base_module_attributes for k, v in iteritems(d)}

        for key, value in iteritems(attrs):
            if isinstance(value, Option):
                value.label = key
                attrs["module_attributes"].update({key: [value.display_value, value.description]})
            elif key == "__info__":
                attrs["_{}{}".format(name, key)] = value
                del attrs[key]
            elif key in attrs["module_attributes"]:  # removing exploit_attribtue that was overwritten
                del attrs["module_attributes"][key]  # in the child and is not an Option() instance

        return super(BaseModuleAggregator, cls).__new__(cls, name, bases, attrs)


class BaseModule(with_metaclass(BaseModuleAggregator, object)):
    @property
    def options(self):
        return list(self.module_attributes.keys())

    def __str__(self):
        return self.__module__.split('.', 2).pop().replace('.', os.sep)

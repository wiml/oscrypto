# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import sys
import inspect


if sys.version_info < (3,):
    str_cls = unicode  # noqa
    byte_cls = str
    int_types = (int, long)  # noqa

    def bytes_to_list(byte_string):
        return [ord(b) for b in byte_string]

else:
    str_cls = str
    byte_cls = bytes
    int_types = (int,)

    bytes_to_list = list


def type_name(value):
    """
    Returns a user-readable name for the type of an object

    :param value:
        A value to get the type name of

    :return:
        A unicode string of the object's type name
    """

    if inspect.isclass(value):
        cls = value
    else:
        cls = value.__class__
    if cls.__module__ in set(['builtins', '__builtin__']):
        return cls.__name__
    return '%s.%s' % (cls.__module__, cls.__name__)


def check_class_type(value, parameter, *classes):
    """
    Checks that a user-supplied parameter is an instance of a given class,
    and raises a TypeError if not.

    :param value:
        The value to check

    :param parameter:
        The name of the parameter by which value was passed.
        Used to produce an informative exception string.

    :param classes:
        One or more class types.
    """

    if not isinstance(value, classes):
        typelist = ' or '.join(aclass.__name__ for aclass in classes)
        raise TypeError(
            '{param} must be an instance of the {desired} class, not {found}'
            .format(
                param=parameter,
                desired=typelist,
                found=type_name(value)
            )
        )

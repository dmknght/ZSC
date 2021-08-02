# https://github.com/threat9/routersploit/blob/master/routersploit/interpreter.py
# Modified by Nong Hoang "DmKnght" Tu for new Owasp ZSC
"""
Copyright 2018, The RouterSploit Framework (RSF) by Threat9
All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

    * Redistributions of source code must retain the above copyright notice, this list of conditions and the
    following disclaimer. * Redistributions in binary form must reproduce the above copyright notice, this list of
    conditions and the following disclaimer in the documentation and/or other materials provided with the
    distribution. * Neither the name of RouterSploit Framework nor the names of its contributors may be used to
    endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The above licensing was taken from the BSD licensing and is applied to RouterSploit Framework as well.

Note that the RouterSploit Framework is provided as is, and is a royalty free open-source application.

Feel free to modify, use, change, market, do whatever you want with it as long as you give the appropriate credit.
"""

from itertools import chain
from future.utils import with_metaclass
import os
import importlib
from owasp_zsc.new_cores import alert
from owasp_zsc.libs import opcoder

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


class OptInt(Option):
    """ Option Integer attribute """

    def __set__(self, instance, value):
        try:
            if not str(value):
                alert.error("Value is empty")
                return
            self.display_value = str(value)
            self.value = int(value)
        except ValueError:
            alert.error(f"Invalid option. Cannot cast '{value}' to integer.")


class OptFile(OptString):
    """Verify if file is valid"""
    def __set__(self, instance, value):
        # When user set file, we are having 2 cases
        # 1. File exists (obfuscate)
        # 2. File doesn't exist (generate)
        # Both cases need file is writable. First case needs file readable
        try:
            # If file exists, we check if file is readable. If not, alert and return
            if os.path.isfile(value):
                if not os.access(value, os.R_OK):
                    alert.error(f"File {value} is not readable")
                    return
            # If file is not there, check if we can read and write file
            folder = os.path.split(value)[0]
            if not os.access(folder, os.W_OK):
                alert.error(f"Folder {folder} is not writable.")

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
            attrs["module_attributes"] = {k: v for d in base_module_attributes for k, v in d.items()}

        for key, value in list(attrs.items()):
            if isinstance(value, Option):
                value.label = key
                attrs["module_attributes"].update({key: [value.display_value, value.description]})
            elif key == "__info__":
                attrs["_{}{}".format(name, key)] = value
                del attrs[key]
            elif key in attrs["module_attributes"]:  # removing exploit_attribtue that was overwritten
                del attrs["module_attributes"][key]  # in the child and is not an Option() instance

        return super(BaseModuleAggregator, cls).__new__(cls, name, bases, attrs)


class OptEncoder(Option):
    """ Option Encoder attribute """

    def __init__(self, default, description=""):
        self.description = description

        if default:
            self.display_value = default
            self.value = default
        else:
            self.display_value = ""
            self.value = None

    def __set__(self, instance, value):
        encoder = instance.get_encoder(value)

        if encoder:
            self.value = encoder
            self.display_value = value
        else:
            raise ValueError("Encoder not available. Check available encoders with `show encoders`.")


class BaseModule(with_metaclass(BaseModuleAggregator, object)):
    @property
    def options(self):
        return list(self.module_attributes.keys())

    def __str__(self):
        return self.__module__.split('.', 2).pop().replace('.', os.sep)


class BasePayload(BaseModule):
    encoder = OptString("", "Encoder")
    file = OptString("", "Output file to write shellcode")
    fmt = None

    def generate(self):
        raise NotImplementedError("Please implement 'generate()' method")

    def get_encoders(self, current_module):
        platform = current_module.split("/")[-2]
        from owasp_zsc.modules import encoders
        path = f"{encoders.__path__[0]}/{platform}"

        encoders = []

        try:
            files = os.listdir(path)
        except FileNotFoundError:
            return []

        for f in files:
            if not f.startswith("__") and f.endswith(".py"):
                encoder = f.replace(".py", "")
                module_path = "{}/{}".format(path, encoder).replace("/", ".").split("owasp_zsc")[1]
                module = getattr(importlib.import_module(f"owasp_zsc{module_path}"), "Encoder")
                encoders.append((
                    f"{platform}/{encoder}",
                    module._Encoder__info__["description"],
                ))
        return encoders

    def get_encoder(self, encoder):
        module_path = "owasp_zsc/modules/encoders/{}".format(encoder).replace("/", ".")
        try:
            module = getattr(importlib.import_module(module_path), "Encoder")
        except ImportError:
            alert.error(f"Failed to import {module_path}")
            return None
        return module()

    def handle_generate(self, name=""):
        alert.info("Generating payload")
        asm_code = self.generate()
        arch = name.split(".")[-2] if "." in name else False
        if not arch:
            alert.error("Invalid arch of module")
            return
        opcode_path = f"{opcoder.__path__[0].split('ZSC/')[1].replace('/', '.')}.{arch}"
        opcode_module = importlib.import_module(opcode_path)
        opcode = getattr(opcode_module, "convert")(asm_code)
        # TODO handle encoder here first
        if not self.file:
            alert.info("ASM code:")
            print(asm_code)
            if opcode:
                alert.info("Opcode:")
                print(f"\"{opcode}\"")
            else:
                alert.warn("No opcode is available")
        else:
            # We do generate code here. Scope: C, ASM, Nim, ...
            # if file is asm, we don't have to have opcode
            print(os.path.splitext(self.file))

        return True

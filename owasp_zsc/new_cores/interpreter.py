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
import readline
from owasp_zsc.modules import payloads
import os
import importlib
from owasp_zsc.new_cores.base_module import GLOBAL_OPTS, BasePayload
from owasp_zsc.new_cores import print_table
from owasp_zsc.new_cores.color import color
from owasp_zsc.new_cores import alert


class BaseInterpreter(object):
    global_help = ""

    def __init__(self):
        self.setup()
        self.banner = ""

    def setup(self):
        """ Initialization of third-party libraries

        Setting interpreter history.
        Setting appropriate completer function.

        :return:
        """
        readline.parse_and_bind("set enable-keypad on")
        readline.set_completer(self.complete)
        readline.set_completer_delims(" \t\n;")
        readline.parse_and_bind("tab: complete")

    def parse_line(self, line):
        """ Split line into command and argument.

        :param line: line to parse
        :return: (command, argument)
        """
        command, _, arg = line.strip().partition(" ")
        return command, arg.strip()

    @property
    def prompt(self):
        """ Returns prompt string """
        return ">>>"

    def get_command_handler(self, command):
        """ Parsing command and returning appropriate handler.

        :param command: command
        :return: command_handler
        """
        try:
            command_handler = getattr(self, "command_{}".format(command))
        except AttributeError:
            raise AttributeError("Unknown command: '{}'".format(command))

        return command_handler

    def start(self):
        """ main entry point. Starting interpreter loop. """
        while True:
            try:
                command, args = self.parse_line(input(self.prompt))
                if not command:
                    continue
                command_handler = self.get_command_handler(command)
                command_handler(args)
            except KeyboardInterrupt:
                print("")
            except AttributeError:
                pass

    def complete(self, text, state):
        """Return the next possible completion for 'text'.

        If a command has not been entered, then complete against command list.
        Otherwise try to call complete_<command> to get list of completions.
        """
        if state == 0:
            original_line = readline.get_line_buffer()
            line = original_line.lstrip()
            stripped = len(original_line) - len(line)
            start_index = readline.get_begidx() - stripped
            end_index = readline.get_endidx() - stripped

            if start_index > 0:
                cmd, args = self.parse_line(line)
                if cmd == "":
                    complete_function = self.default_completer
                else:
                    try:
                        complete_function = getattr(self, "complete_" + cmd)
                    except AttributeError:
                        complete_function = self.default_completer
            else:
                complete_function = self.raw_command_completer

            self.completion_matches = complete_function(text, line, start_index, end_index)

        try:
            return self.completion_matches[state]
        except IndexError:
            return None

    def commands(self, *ignored):
        """ Returns full list of interpreter commands.

        :param ignored:
        :return: full list of interpreter commands
        """
        return [command.rsplit("_").pop() for command in dir(self) if command.startswith("command_")]

    def raw_command_completer(self, text, line, start_index, end_index):
        """ Complete command w/o any argument """
        return [command for command in self.suggested_commands() if command.startswith(text)]

    def default_completer(self, *ignored):
        return []

    def suggested_commands(self):
        """ Entry point for intelligent tab completion.

        Overwrite this method to suggest suitable commands.

        :return: list of suitable commands
        """
        return self.commands()


class ZscInterpreter(BaseInterpreter):
    def __init__(self):
        super(ZscInterpreter, self).__init__()

        self.current_module = None
        self.raw_prompt_template = None
        self.module_prompt_template = None
        self.main_commands = (
            ("about", "Show information of program"),
            ("use ", "Use a module"),
            ("help", "Show help menu"),
            ("exit", "Exit program"),
        )
        self.module_commands = (
            ("run", "Run current module"),
            ("back", "Return to main module"),
            ("set ", "Set value for an option"),
            ("show options", "Show options of current module"),
            ("help", "Show help menu"),
        )
        self.all_modules = self.get_modules()

    def get_modules(self):
        module_path = payloads.__path__[0] + "/"
        ret_modules = []
        for root, dirs, files in os.walk(module_path):
            _, package, root = root.rpartition(module_path.replace("/", os.sep))
            root = root.replace(os.sep, ".")
            files = filter(lambda x: not x.startswith("__") and x.endswith(".py"), files)
            ret_modules.extend(map(lambda x: ".".join((root, os.path.splitext(x)[0])), files))

        return ret_modules

    @property
    def prompt(self):
        """ Returns prompt string based on current_module attribute.

        Adding module prefix (module.name) if current_module attribute is set.

        :return: prompt string with appropriate module prefix.
        """
        if self.current_module:
            return f"{color('cyan')}ZSC{color('reset')}[{color('purple')}{self.current_module}{color('reset')}]> "
        else:
            return f"{color('cyan')}ZSC{color('reset')}> "

    def suggested_commands(self):
        """ Entry point for intelligent tab completion.

        Based on state of interpreter this method will return intelligent suggestions.

        :return: list of most accurate command suggestions
        """
        if not self.current_module:
            return [x[0] for x in self.main_commands]
        else:
            return [x[0] for x in self.module_commands]

    def command_back(self, *args, **kwargs):
        self.current_module = None

    def command_help(self, *args, **kwargs):
        if self.current_module:
            for command, descriptions in self.module_commands:
                print(f"  {command:15}  {descriptions}")
        else:
            for command, descriptions in self.main_commands:
                print(f"  {command:15}  {descriptions}")

    # def command_search(self, *args, **kwargs):
    #     pass

    def command_exit(self, *args, **kwargs):
        exit()

    def command_quit(self, *args, **kwargs):
        exit()

    def complete_use(self, text, *args, **kwargs):
        if text.endswith(".") or not text:
            # Try to suggest new layer
            return [x.replace(text, "").split(".")[0] for x in self.all_modules if x.startswith(text)]
        else:
            # Try to suggest maximum layer
            return [x for x in self.all_modules if x.startswith(text)]

    def command_use(self, module_path, *args, **kwargs):
        module_path = ".".join(("owasp_zsc.modules.payloads", module_path))
        try:
            module = importlib.import_module(module_path)
            self.current_module = getattr(module, "Module")()
        except:
            print(self.current_module.__attr)

    def command_run(self, *args, **kwargs):
        if not self.current_module:
            return
        self.current_module.run()

    def command_set(self, *args, **kwargs):
        if not self.current_module:
            return
        key, _, value = args[0].partition(" ")
        if key in self.current_module.options:
            if str(self.current_module) == "payloads/obfuscator/obfuscate" and key == "file":
                # Specific set for module obfuscate
                # Check if file exists
                if not os.path.isfile(value):
                    alert.error(f"Error: {value} is not a file\n")
                    return
                # Parse file extension to set arguments automatically
                file_name, file_ext = os.path.splitext(value)
                # If no extension, we try shebang. Have to deal with binary files
                if not file_ext:
                    alert.error(f"{value} might be a valid file. But shebang parsing isn't supported.")
                else:
                    if file_ext == ".py":
                        module_type = "python"
                    elif file_ext.lower() == ".js":
                        module_type = "javascript"
                    elif file_ext.lower() == ".pl":
                        module_type = "perl"
                    elif file_ext.lower() == ".rb":
                        module_type = "ruby"
                    elif file_ext.lower().startswith(".php"):
                        module_type = "php"
                    else:
                        alert.error("Unsupported language\n")
                        return

                    # Set module_type
                    alert.info(f"Detected {module_type}")
                    setattr(self.current_module, "type", module_type)
                    self.current_module.module_attributes["type"][0] = module_type
                    # Get valid submodules for each module types
                    from owasp_zsc.lib import obfuscate
                    available_modules = [os.path.splitext(x)[0] for x in
                                         os.listdir(obfuscate.__path__[0] + "/" + module_type) if
                                         x.endswith(".py") and not x.startswith("__")]
                    alert.info(f"Modules for {module_type}: {available_modules}")

            setattr(self.current_module, key, value)
            self.current_module.module_attributes[key][0] = value
            if kwargs.get("glob", False):
                GLOBAL_OPTS[key] = value
            print(f"{key} => {value}")  # TODO fix here when value failed to set
        else:
            print(f"You can't set option '{key}'.\n"
                  f"Available options: {self.current_module.options}")

    def complete_set(self, text, *args, **kwargs):
        if text:
            return [" ".join((attr, "")) for attr in self.current_module.options if attr.startswith(text)]
        else:
            return self.current_module.options

    def get_opts(self, *args):
        """ Generator returning module's Option attributes (option_name, option_value, option_description)

        :param args: Option names
        :return:
        """
        for opt_key in args:
            try:
                opt_description = self.current_module.module_attributes[opt_key][1]
                opt_display_value = self.current_module.module_attributes[opt_key][0]
            except (KeyError, AttributeError):
                pass
            else:
                yield opt_key, opt_display_value, opt_description

    def _show_encoders(self, *args, **kwargs):
        try:
            import traceback
            if issubclass(self.current_module.__class__, BasePayload):
                encoders = self.current_module.get_encoders(str(self.current_module))
                if encoders:
                    headers = ("Encoder", "Name", "Description")
                    print_table(headers, *encoders, max_column_length=100)
                    return
                else:
                    print("No encoders available")
            else:
                print(self.current_module.__class__)
                print("Module doesn't support encoders")
        except:
            traceback.print_exc()

    def _show_options(self, *args, **kwargs):
        module_opts = [opt for opt in self.current_module.options]
        headers = ("Name", "Current settings", "Description")

        if module_opts:
            print("\nModule options:")
            print_table(headers, *self.get_opts(*module_opts))

    def command_show(self, *args, **kwargs):
        sub_command = args[0]
        try:
            getattr(self, "_show_{}".format(sub_command))(*args, **kwargs)
        except AttributeError:
            print(f"Unknown 'show' sub-command '{sub_command}'. What do you want to show?\n")

    # def complete_show(self, text, *args, **kwargs):
    #     return ["options", "encoders"]
    def complete_show(self, text, *args, **kwargs):
        if text:
            return [command for command in ["options", "encoders"] if command.startswith(text)]
        else:
            return ["options", "encoders"]


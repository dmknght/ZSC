"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
"""
# import sys
# import os
# from cores.compatible import *
# from cores.alert import *
import readline
from cores.commands import *
from lib.shell_storm_api.grab import search_shellcode
from lib.shell_storm_api.grab import download_shellcode
from lib.shell_storm_api.grab import grab_all
from cores.encode import encode_process
from cores.get_input import _input
from cores.opcoder import op
from cores.obfuscate import obf_code
from cores.file_out import file_output
from cores.commands import _help
from cores.compatible import version


class AutoComplete(object):
    def __init__(self, options):
        self.options = sorted(options)
        self.matches = []

    def complete(self, text, state):
        if state == 0:
            if text:
                self.matches = [s for s in self.options
                                if s and s.startswith(text)]
            else:
                self.matches = self.options[:]
        try:
            return self.matches[state]
        except IndexError:
            return None


def get_command(usr_command):
    backup_commands = usr_command
    crawler = 0
    command_path = ['zsc']
    command = ''
    while True:
        try:
            command = _input('/'.join(command_path), 'any', False)
        except KeyboardInterrupt:
            pass
        except:
            warn('interrupted by user!\nExit\n')
            sys.exit(0)
        check = True

        if command and command.startswith('#'):  # allows for comments
            continue

        inContext = ['clear', 'help', 'about', 'version', 'back']
        for option in usr_command:
            if command == option and command not in inContext:
                crawler += 1
                if crawler == 1:
                    usr_command = usr_command[option][1]
                    command_path.append(option)
                if crawler == 2:
                    if command == 'search':
                        search_shellcode(False, 0)
                        usr_command = backup_commands
                        completer = AutoComplete(usr_command)
                        readline.set_completer(completer.complete)
                        readline.parse_and_bind('tab: complete')
                        crawler = 0
                        command_path = ['zsc']
                    elif command == 'download':
                        download_shellcode(False, 0, '')
                        usr_command = backup_commands
                        completer = AutoComplete(usr_command)
                        readline.set_completer(completer.complete)
                        readline.parse_and_bind('tab: complete')
                        crawler = 0
                        command_path = ['zsc']
                    elif command == 'shell_storm_list':
                        grab_all()
                        usr_command = backup_commands
                        completer = AutoComplete(usr_command)
                        readline.set_completer(completer.complete)
                        readline.parse_and_bind('tab: complete')
                        crawler = 0
                        command_path = ['zsc']
                    elif command == 'generate':
                        usr_command = usr_command[option]
                        command_path.append(option)
                    else:
                        while True:
                            f = []
                            import os as OS
                            for (dirpath, dirnames, filenames) in OS.walk('.'):
                                f.extend(filenames)
                                break
                            completer = AutoComplete(f)
                            readline.set_completer(completer.complete)
                            filename = _input('filename', 'any', True)
                            completer = AutoComplete(usr_command)
                            readline.set_completer(completer.complete)
                            try:
                                content = open(filename, 'rb').read()
                                break
                            except:
                                warn('sorry, cann\'t find file\n')
                        usr_command = usr_command[option]
                        command_path.append(option)
                        completer = AutoComplete(usr_command)
                        readline.set_completer(completer.complete)
                        readline.parse_and_bind('tab: complete')
                        t = True
                        while t:
                            encode = _input('encode', 'any', True)
                            for en in usr_command:
                                if encode == en:
                                    t = False
                            if t == True:
                                warn('please enter a valid encode name\n')
                        obf_code(option, encode, filename, content, False)
                        usr_command = backup_commands
                        completer = AutoComplete(usr_command)
                        readline.set_completer(completer.complete)
                        readline.parse_and_bind('tab: complete')
                        crawler = 0
                        command_path = ['zsc']
                if crawler == 3:
                    os = option
                    usr_command = usr_command[option]
                    command_path.append(option)
                if crawler == 4:
                    func = option
                    usr_command = usr_command[option]
                    command_path.append(option)
                if crawler == 5:
                    data = []
                    backup_option = option
                    if option != '':
                        options = option.rsplit('&&')
                        for o in options:
                            data.append(_input(o, 'any', True))
                        n = 0
                        write('\n')
                        for o in options:
                            info('%s set to "%s"\n' % (o, data[n]))
                            n += 1
                    run = getattr(
                        __import__('lib.generator.%s.%s' % (os, func),
                                   fromlist=['run']),
                        'run')
                    shellcode = run(data)
                    write('\n')
                    for encode in backup_commands['shellcode'][1]['generate'][
                        os][func][backup_option]:
                        info(encode + '\n')
                    write('\n\n')
                    info('enter encode type\n')
                    completer = AutoComplete(backup_commands['shellcode'][1][
                                                 'generate'][os][func][backup_option])
                    readline.set_completer(completer.complete)
                    readline.parse_and_bind('tab: complete')
                    try:
                        encode = _input('/'.join(command_path) + "/encode_type", 'any', False)
                        # if encode == None:
                        #     _lets_error
                    except:
                        encode = 'none'
                        warn(
                            '\n"none" encode selected\n')
                    write('\n')
                    assembly_code_or_not = _input(
                        'Output assembly code?(y or n)', 'any', True)
                    if assembly_code_or_not == 'y':
                        assembly_code = True
                    else:
                        assembly_code = False
                    if assembly_code == True:
                        write('\n' + encode_process(encode, shellcode, os, func) + '\n\n')
                    output_shellcode = _input('Output shellcode to screen?(y or n)', 'any', True)
                    shellcode_op = op(encode_process(encode, shellcode, os, func), os)
                    if output_shellcode == 'y':
                        info('Generated shellcode is:\n' + shellcode_op + '\n\n')
                    file_or_not = _input('Shellcode output to a .c file?(y or n)', 'any', True)
                    if file_or_not == 'y':
                        target = _input('Target .c file?', 'any', True)
                        file_output(target, func, data, os, encode, shellcode, shellcode_op)
                    usr_command = backup_commands
                    completer = AutoComplete(usr_command)
                    readline.set_completer(completer.complete)
                    readline.parse_and_bind('tab: complete')
                    crawler = 0
                    command_path = ['zsc']
                completer = AutoComplete(usr_command)
                readline.set_completer(completer.complete)
                readline.parse_and_bind('tab: complete')
                check = False
        if command == 'exit' or command == 'quit':
            write(color.color('reset'))
            sys.exit('Exit')
        elif command == 'help':
            _help(commands_help)
        elif command == 'restart':
            usr_command = backup_commands
            completer = AutoComplete(usr_command)
            readline.set_completer(completer.complete)
            readline.parse_and_bind('tab: complete')
            crawler = 0
            command_path = ['zsc']
        elif command == 'about':
            about()
        elif command == 'version':
            version()
        elif command == 'back':
            if len(command_path) > 1:
                command_path.pop()
                usr_command = backup_commands
                for option in command_path:
                    if option == 'zsc':
                        pass
                    elif option == command_path[1]:
                        usr_command = usr_command[option][1]
                    else:
                        usr_command = usr_command[option]
                completer = AutoComplete(usr_command)
                readline.set_completer(completer.complete)
                readline.parse_and_bind('tab: complete')
                crawler -= 1
            else:
                info('Can\'t go back from here!\n')
        else:
            if command != '' and check == True:
                info('Command not found!\n')


def engine(usr_commands):
    """ engine function"""
    completer = AutoComplete(usr_commands)
    readline.set_completer(completer.complete)
    readline.parse_and_bind('tab: complete')
    get_command(usr_commands)

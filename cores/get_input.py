"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
"""
from cores.compatible import *
from cores.alert import *
import binascii


def _input(name, var_type, _while):
    data = None
    if _while:
        if var_type == 'any':
            while _while:
                try:
                    data = input('%s%s>%s ' % (color.color('blue'), name, color.color('yellow')))
                    if data == '':
                        warn('input can\'t be empty! ')
                    # _lets_error
                    break
                except:
                    write('wrong input!\n')
                    pass
        if var_type == 'hex':
            while _while:
                try:
                    data = input(f"{color.color('blue')}{name}>{color.color('yellow')}")
                    # data = input('%s%s>%s ' % (color.color('blue'), name,
                    #                            color.color('yellow')))
                    # data = input(f"{color.color('blue')}{name}>{color.color('yellow')}")
                    binascii.b2a_hex(data[::-1].encode('latin-1')).decode('latin-1')
                    if not data:
                        warn('input can\'t be empty! ')
                    # _lets_error
                    break
                except:
                    warn('you must enter a hex value\n')
                    pass
        if var_type == 'int':
            while _while:
                try:
                    data = input('%s%s>%s ' % (color.color('blue'), name,
                                               color.color('yellow')))
                    int(data)  # if empty, jump to exception and error!
                    break
                except:
                    warn('you must enter a int value\n')
                    pass
    elif not _while:
        if var_type == 'any':
            try:
                data = input('%s%s>%s ' % (color.color('blue'), name,
                                           color.color('yellow')))
            except:
                write('wrong input!\n')
                pass
        if var_type == 'hex':
            try:
                data = input('%s%s>%s ' % (color.color('blue'), name,
                                           color.color('yellow')))
                binascii.b2a_hex(data[::-1].encode('latin-1')).decode(
                    'latin-1')
            except:
                warn('you must enter a hex value\n')
                pass
        if var_type == 'int':
            try:
                data = input('%s%s>%s ' % (color.color('blue'), name,
                                           color.color('yellow')))
                int(data)
            except:
                warn('you must enter a int value\n')
                pass
    return data

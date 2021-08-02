"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""


def encode_process(encode, shellcode, os, func):
    if encode == 'none':
        return shellcode
    elif 'linux_x86' == os:
        if encode == 'add_random':
            from owasp_zsc.lib.encoders.linux_x86.add_random import start
            return start(shellcode, func)
        elif 'add_' in encode:
            from owasp_zsc.lib.encoders.linux_x86.add_yourvalue import start
            return start(encode, shellcode, func)
        elif encode == 'dec':
            from owasp_zsc.lib.encoders.linux_x86.dec import start
            return start(shellcode, func)
        elif 'dec_' in encode:
            from owasp_zsc.lib.encoders.linux_x86 import start
            return start(encode, shellcode, func)
        elif encode == 'inc':
            from owasp_zsc.lib.encoders.linux_x86 import start
            return start(shellcode, func)
        elif 'inc_' in encode:
            from owasp_zsc.lib.encoders.linux_x86.inc_timesyouwant import start
            return start(encode, shellcode, func)
        elif encode == 'mix_all':
            from owasp_zsc.lib.encoders.linux_x86.mix_all import start
            return start(shellcode, func)
        elif encode == 'sub_random':
            from owasp_zsc.lib.encoders.linux_x86.sub_random import start
            return start(shellcode, func)
        elif 'sub_' in encode:
            from owasp_zsc.lib.encoders.linux_x86.sub_yourvalue import start
            return start(encode, shellcode, func)
        elif encode == 'xor_random':
            from owasp_zsc.lib.encoders.linux_x86 import start
            return start(shellcode, func)
        elif 'xor_' in encode:
            from owasp_zsc.lib.encoders.linux_x86.xor_yourvalue import start
            return start(encode, shellcode, func)
    elif 'windows_x86' == os:
        if encode == 'xor_random':
            from owasp_zsc.lib.encoders.windows_x86 import start
            return start(shellcode, func)
        elif encode == 'add_random':
            from owasp_zsc.lib.encoders.windows_x86.add_random import start
            return start(shellcode, func)
        elif encode == 'sub_random':
            from owasp_zsc.lib.encoders.windows_x86 import start
            return start(shellcode, func)
        elif encode == 'inc':
            from owasp_zsc.lib.encoders.windows_x86 import start
            return start(shellcode, func)
        elif encode == 'dec':
            from owasp_zsc.lib.encoders.windows_x86 import start
            return start(shellcode, func)
        elif 'xor_' in encode:
            from owasp_zsc.lib.encoders.windows_x86 import start
            return start(encode, shellcode, func)
        elif 'inc_' in encode:
            from owasp_zsc.lib.encoders.windows_x86 import start
            return start(encode, shellcode, func)
        elif 'dec_' in encode:
            from owasp_zsc.lib.encoders.windows_x86 import start
            return start(encode, shellcode, func)
        elif 'add_' in encode:
            from owasp_zsc.lib.encoders.windows_x86.add_yourvalue import start
            return start(encode, shellcode, func)
        elif 'sub_' in encode:
            from owasp_zsc.lib.encoders.windows_x86 import start
            return start(encode, shellcode, func)
    elif 'osx_x86' == os:
        if encode == 'add_random':
            from owasp_zsc.lib.encoders.osx_x86.add_random import start
            return start(shellcode, func)
        elif 'add_' in encode:
            from owasp_zsc.lib.encoders.osx_x86.add_yourvalue import start
            return start(encode, shellcode, func)
        elif encode == 'dec':
            from owasp_zsc.lib.encoders.osx_x86.dec import start
            return start(shellcode, func)
        elif 'dec_' in encode:
            from owasp_zsc.lib.encoders.osx_x86.dec_timesyouwant import start
            return start(encode, shellcode, func)
        elif encode == 'inc':
            from owasp_zsc.lib.encoders.osx_x86.inc import start
            return start(shellcode, func)
        elif 'inc_' in encode:
            from owasp_zsc.lib.encoders.osx_x86.inc_timesyouwant import start
            return start(encode, shellcode, func)
        elif encode == 'sub_random':
            from owasp_zsc.lib.encoders.osx_x86.sub_random import start
            return start(shellcode, func)
        elif 'sub_' in encode:
            from owasp_zsc.lib.encoders.osx_x86.sub_yourvalue import start
            return start(encode, shellcode, func)
        elif encode == 'xor_random':
            from owasp_zsc.lib.encoders.osx_x86 import start
            return start(shellcode, func)
        elif 'xor_' in encode:
            from owasp_zsc.lib.encoders.osx_x86.xor_yourvalue import start
            return start(encode, shellcode, func)
    return shellcode

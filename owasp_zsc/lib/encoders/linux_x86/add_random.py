
"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
import binascii
import random
import string

chars = string.digits + string.ascii_letters


def chmod(shellcode):
    eax = str('0x0f')
    while True:
        eax_1 = (binascii.b2a_hex((''.join(random.choice(chars) for i in range(1))).encode('latin-1'))).decode('latin-1')
        eax_1 = str('0') + str(eax_1[1])
        eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        if eax > eax_1:
            if '00' not in str(eax_1) and '00' not in str(eax_2):
                break
    eax = f"push ${str(eax)}"
    eax_add = f'push $0x{eax_1}\npop %eax\npush $0x{eax_2}\npop %ebx\nadd %eax,%ebx\npush %ebx\n'
    shellcode = shellcode.replace(eax, eax_add)
    ebx = str(shellcode.rsplit('\n')[8])
    ebx_value = str(shellcode.rsplit('\n')[8].rsplit()[1][1:])

    while True:
        ebx_1 = (binascii.b2a_hex((''.join(random.choice(chars) for i in range(4))).encode('latin-1'))).decode('latin-1')
        ebx_2 = "%x" % (int(ebx_value, 16) - int(ebx_1, 16))
        if '00' not in str(ebx_1) and '00' not in str(ebx_2) and \
                int(len(ebx_1)) >= 7 and int(len(ebx_2)) >= 7 and '-' in ebx_2:
            break
    ebx_2 = ebx_2.replace('-', '')
    ebx_add = f"push $0x{str(ebx_1)}\npop %ebx\npush $0x{str(ebx_2)}\npop %ecx\nneg %ecx\n"
    ebx_add += "add %ecx,%ebx\npush %ebx\n_z3r0d4y_\n"
    shellcode = shellcode.replace(ebx, ebx_add)
    n = 0
    code_start = ''
    middle = ''
    end = ''
    add = 0
    for char in shellcode.rsplit('\n'):
        n += 1
        if add == 0:
            if '_z3r0d4y_' not in char:
                code_start += char + '\n'
            else:
                add = 1
        if add == 1:
            if '_z3r0d4y_' not in char:
                if '%esp,%ebx' not in char:
                    middle += char + '\n'
                else:
                    add = 2
        if add == 2:
            end += char + '\n'

    for char in middle.rsplit('\n'):
        while True:
            if 'push $0x' in char:
                edx = char.rsplit()[1][1:]
                edx_1 = binascii.b2a_hex(
                    (''.join(random.choice(chars) for i in range(4))).encode('latin-1')).decode('latin-1')
                edx_2 = "%x" % (int(edx[2:], 16) - int(edx_1, 16))
                if '00' not in str(edx_1) and '00' not in str(edx_2) and \
                        '-' in edx_2 and int(len(edx_2)) >= 7 and int(len(edx_1)) >= 7 and '-' not in edx_1:
                    edx_2 = edx_2.replace('-', '')
                    command = f"\npush $0x{str(edx_1)}\npop %ebx\npush $0x{str(edx_2)}\n"
                    command += "pop %edx\nneg %edx\nadd %ebx,%edx\npush %edx\n"
                    middle = middle.replace(char, command)
                    break
            else:
                break
    shellcode = code_start + middle + end
    return shellcode


def dir_create(shellcode):
    shellcode = 'xor %edx, %edx\n' + shellcode.replace('push $0xb\npop %eax\ncltd', '').replace('push %ebx\nmov %esp,%ecx', 'push %ebx\nmov %esp,%ecx\npush $0xb\npop %eax\ncltd')
    eax = str('0xb')
    while True:
        eax_1 = binascii.b2a_hex((''.join(random.choice(chars) for i in range(1))).encode('latin-1')).decode('latin-1')
        eax_1 = str('0') + str(eax_1[1])
        eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        if eax > eax_1:
            if '00' not in str(eax_1) and '00' not in str(eax_2):
                break
    eax = f"push  ${str(eax)}"
    if '-' in eax_2:
        eax_2 = eax_2.replace('-', '')
        eax_add = f"push $0x{eax_2}\npop %eax\nneg %eax\nadd $0x{eax_1},%eax\n"
    else:
        eax_add = f"push $0x{eax_2}\npop %eax\nadd $0x{eax_1},%eax\n"
    shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd', eax_add + '\ncltd\n')
    for line in shellcode.rsplit('\n'):
        if 'push' in line and '$0x' in line and ',' not in line and len(line) > 14:
            data = line.rsplit('push')[1].rsplit('$0x')[1]
            while True:
                ebx_1 = (binascii.b2a_hex((''.join(random.choice(chars) for i in range(4))).encode('latin-1'))).decode('latin-1')
                ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))

                if str('00') not in str(ebx_1) and str('00') not in str(ebx_2) and '-' in ebx_2 and len(ebx_2) >= 7 and len(ebx_1) >= 7 and '-' not in ebx_1:
                    ebx_2 = ebx_2.replace('-', '')
                    command = f"\npush $0x{str(ebx_1)}\npop %ebx\npush $0x{str(ebx_2)}\npop %eax\nneg %eax\nadd %ebx,%eax\npush %eax\n"
                    shellcode = shellcode.replace(line, command)
                    break
    return shellcode


def download_execute(shellcode):
    shellcode = 'xor %edx, %edx\n' + shellcode.replace('push $0xb\npop %eax\ncltd', '').replace('push %ebx\nmov %esp, %ecx', 'push   %ebx\nmov %esp,%ecx\npush $0xb\npop %eax\ncltd')
    t = True
    eax = str('0xb')
    while t:
        eax_1 = (binascii.b2a_hex((''.join(random.choice(chars) for i in range(1))).encode('latin-1'))).decode('latin-1')
        eax_1 = str('0') + str(eax_1[1])
        eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        if eax > eax_1:
            if '00' not in str(eax_1) and '00' not in str(eax_2):
                t = False
    A = 0
    eax = 'push   $%s' % (str(eax))
    if '-' in eax_2:
        A = 1
        eax_2 = eax_2.replace('-', '')
        eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
            eax_2, eax_1)

    if A == 0:
        eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
                                                                eax_1)
    shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',
                                  eax_add + '\ncltd\n')
    for line in shellcode.rsplit('\n'):
        if 'push' in line and '$0x' in line and ',' not in line and len(
                line) > 14:
            data = line.rsplit('push')[1].rsplit('$0x')[1]
            t = True
            while t:
                ebx_1 = (binascii.b2a_hex((''.join(random.choice(
                    chars) for i in range(4))).encode('latin-1'))
                         ).decode('latin-1')
                ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))

                if str('00') not in str(ebx_1) and str('00') not in str(
                        ebx_2) and '-' in ebx_2 and len(
                    ebx_2) >= 7 and len(
                    ebx_1) >= 7 and '-' not in ebx_1:
                    ebx_2 = ebx_2.replace('-', '')
                    command = '\npush $0x%s\npop %ebx\npush $0x%s\npop %eax\nneg %eax\nadd %ebx,%eax\npush %eax\n' % (
                        str(ebx_1), str(ebx_2))
                    shellcode = shellcode.replace(line, command)
                    t = False


def download(shellcode):
    shellcode = 'xor %edx,%edx\n' + shellcode.replace(
        'push   $0xb\npop    %eax\ncltd',
        '').replace('push   %ebx\nmov    %esp,%ecx',
                    'push   %ebx\nmov    %esp,%ecx' + '\n' +
                    'push   $0xb\npop    %eax\ncltd')
    t = True
    eax = str('0xb')
    while t:
        eax_1 = (binascii.b2a_hex((''.join(random.choice(
            chars) for i in range(1))).encode('latin-1'))
                 ).decode('latin-1')
        eax_1 = str('0') + str(eax_1[1])
        eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        if eax > eax_1:
            if '00' not in str(eax_1) and '00' not in str(eax_2):
                t = False
    A = 0
    eax = 'push   $%s' % (str(eax))
    if '-' in eax_2:
        A = 1
        eax_2 = eax_2.replace('-', '')
        eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
            eax_2, eax_1)

    if A == 0:
        eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
                                                                eax_1)
    shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',
                                  eax_add + '\ncltd\n')
    for line in shellcode.rsplit('\n'):
        if 'push' in line and '$0x' in line and ',' not in line and len(
                line) > 14:
            data = line.rsplit('push')[1].rsplit('$0x')[1]
            t = True
            while t:
                ebx_1 = (binascii.b2a_hex((''.join(random.choice(
                    chars) for i in range(4))).encode('latin-1'))
                         ).decode('latin-1')
                ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))

                if str('00') not in str(ebx_1) and str('00') not in str(
                        ebx_2) and '-' in ebx_2 and len(
                    ebx_2) >= 7 and len(
                    ebx_1) >= 7 and '-' not in ebx_1:
                    ebx_2 = ebx_2.replace('-', '')
                    command = '\npush $0x%s\npop %ebx\npush $0x%s\npop %eax\nneg %eax\nadd %ebx,%eax\npush %eax\n' % (
                        str(ebx_1), str(ebx_2))
                    shellcode = shellcode.replace(line, command)
                    t = False


def exec(shellcode):
    t = True
    eax = str('0x46')
    while t:
        eax_1 = (binascii.b2a_hex((''.join(random.choice(
            chars) for i in range(1))).encode('latin-1'))
                 ).decode('latin-1')
        eax_1 = str('0') + str(eax_1[1])
        eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        if eax > eax_1:
            if '00' not in str(eax_1) and '00' not in str(eax_2):
                t = False

    A = 0
    eax = 'push   $%s' % (str(eax))
    if '-' in eax_2:
        A = 1
        eax_2 = eax_2.replace('-', '')
        eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
            eax_2, eax_1)

    if A == 0:
        eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
                                                                eax_1)
    shellcode = shellcode.replace('mov    $0x46,%al', eax_add)
    for line in shellcode.rsplit('\n'):
        if 'push' in line and '$0x' in line and ',' not in line and len(
                line) > 14:
            data = line.rsplit('push')[1].rsplit('$0x')[1]
            t = True
            while t:
                ebx_1 = (binascii.b2a_hex((''.join(random.choice(
                    chars) for i in range(4))).encode('latin-1'))
                         ).decode('latin-1')
                ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))
                if str('00') not in str(ebx_1) and str('00') not in str(
                        ebx_2) and '-' in ebx_2 and len(ebx_2.replace(
                    '-', '')) >= 7 and len(
                    ebx_1) >= 7 and '-' not in ebx_1:
                    ebx_2 = ebx_2.replace('-', '')
                    command = '\npush $0x%s\npop %ebx\npush $0x%s\npop %eax\nneg %eax\nadd %ebx,%eax\npush %eax\n' % (
                        str(ebx_1), str(ebx_2))
                    shellcode = shellcode.replace(line, command)
                    t = False


def file_create(shellcode):
    shellcode = 'xor %edx,%edx\n' + shellcode.replace(
        'push   $0xb\npop    %eax\ncltd',
        '').replace('push   %ebx\nmov    %esp,%ecx',
                    'push   %ebx\nmov    %esp,%ecx' + '\n' +
                    'push   $0xb\npop    %eax\ncltd')
    t = True
    eax = str('0xb')
    while t:
        eax_1 = (binascii.b2a_hex((''.join(random.choice(
            chars) for i in range(1))).encode('latin-1'))
                 ).decode('latin-1')
        eax_1 = str('0') + str(eax_1[1])
        eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        if eax > eax_1:
            if '00' not in str(eax_1) and '00' not in str(eax_2):
                t = False
    A = 0
    eax = 'push   $%s' % (str(eax))
    if '-' in eax_2:
        A = 1
        eax_2 = eax_2.replace('-', '')
        eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
            eax_2, eax_1)

    if A == 0:
        eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
                                                                eax_1)
    shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',
                                  eax_add + '\ncltd\n')
    for line in shellcode.rsplit('\n'):
        if 'push' in line and '$0x' in line and ',' not in line and len(
                line) > 14:
            data = line.rsplit('push')[1].rsplit('$0x')[1]
            t = True
            while t:
                ebx_1 = (binascii.b2a_hex((''.join(random.choice(
                    chars) for i in range(4))).encode('latin-1'))
                         ).decode('latin-1')
                ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))

                if str('00') not in str(ebx_1) and str('00') not in str(
                        ebx_2) and '-' in ebx_2 and len(
                    ebx_2) >= 7 and len(
                    ebx_1) >= 7 and '-' not in ebx_1:
                    ebx_2 = ebx_2.replace('-', '')
                    command = '\npush $0x%s\npop %ebx\npush $0x%s\npop %eax\nneg %eax\nadd %ebx,%eax\npush %eax\n' % (
                        str(ebx_1), str(ebx_2))
                    shellcode = shellcode.replace(line, command)
                    t = False


def script_executor(shellcode):
    shellcode = 'xor %edx,%edx\n' + shellcode.replace(
        'push   $0xb\npop    %eax\ncltd',
        '').replace('push   %ebx\nmov    %esp,%ecx',
                    'push   %ebx\nmov    %esp,%ecx' + '\n' +
                    'push   $0xb\npop    %eax\ncltd')
    t = True
    eax = str('0xb')
    while t:
        eax_1 = (binascii.b2a_hex((''.join(random.choice(
            chars) for i in range(1))).encode('latin-1'))
                 ).decode('latin-1')
        eax_1 = str('0') + str(eax_1[1])
        eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        if eax > eax_1:
            if '00' not in str(eax_1) and '0' not in str(eax_2):
                t = False
    A = 0
    eax = 'push   $%s' % (str(eax))
    if '-' in eax_2:
        A = 1
        eax_2 = eax_2.replace('-', '')
        eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
            eax_2, eax_1)

    if A == 0:
        eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
                                                                eax_1)
    shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',
                                  eax_add + '\ncltd\n')
    for line in shellcode.rsplit('\n'):
        if 'push' in line and '$0x' in line and ',' not in line and len(
                line) > 14:
            data = line.rsplit('push')[1].rsplit('$0x')[1]
            t = True
            while t:
                ebx_1 = (binascii.b2a_hex((''.join(random.choice(
                    chars) for i in range(4))).encode('latin-1'))
                         ).decode('latin-1')
                ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))

                if str('00') not in str(ebx_1) and str('00') not in str(
                        ebx_2) and '-' in ebx_2 and len(
                    ebx_2) >= 7 and len(
                    ebx_1) >= 7 and '-' not in ebx_1:
                    ebx_2 = ebx_2.replace('-', '')
                    command = '\npush $0x%s\npop %ebx\npush $0x%s\npop %eax\nneg %eax\nadd %ebx,%eax\npush %eax\n' % (
                        str(ebx_1), str(ebx_2))
                    shellcode = shellcode.replace(line, command)
                    t = False


def system(shellcode):
    shellcode = 'xor %edx,%edx\n' + shellcode.replace(
        'push   $0xb\npop    %eax\ncltd',
        '').replace('push   %ebx\nmov    %esp,%ecx',
                    'push   %ebx\nmov    %esp,%ecx' + '\n' +
                    'push   $0xb\npop    %eax\ncltd')
    t = True
    eax = str('0xb')
    while t:
        eax_1 = (binascii.b2a_hex((''.join(random.choice(
            chars) for i in range(1))).encode('latin-1'))
                 ).decode('latin-1')
        eax_1 = str('0') + str(eax_1[1])
        eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        if eax > eax_1:
            if '00' not in str(eax_1) and '0' not in str(eax_2):
                t = False
    A = 0
    eax = 'push   $%s' % (str(eax))
    if '-' in eax_2:
        A = 1
        eax_2 = eax_2.replace('-', '')
        eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
            eax_2, eax_1)
    if A == 0:
        eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
                                                                eax_1)
    shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',
                                  eax_add + '\ncltd\n')
    for line in shellcode.rsplit('\n'):
        if 'push' in line and '$0x' in line and ',' not in line and len(
                line) > 14:
            data = line.rsplit('push')[1].rsplit('$0x')[1]
            t = True
            while t:
                ebx_1 = (binascii.b2a_hex((''.join(random.choice(
                    chars) for i in range(4))).encode('latin-1'))
                         ).decode('latin-1')
                ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))

                if str('00') not in str(ebx_1) and str('00') not in str(
                        ebx_2) and '-' in ebx_2 and len(
                    ebx_2) >= 7 and len(
                    ebx_1) >= 7 and '-' not in ebx_1:
                    ebx_2 = ebx_2.replace('-', '')
                    command = '\npush $0x%s\npop %ebx\npush $0x%s\npop %eax\nneg %eax\nadd %ebx,%eax\npush %eax\n' % (
                        str(ebx_1), str(ebx_2))
                    shellcode = shellcode.replace(line, command)
                    t = False


def write(shellcode):
    t = True
    eax = str('0x5')
    while t:
        eax_1 = (binascii.b2a_hex((''.join(random.choice(
            chars) for i in range(1))).encode('latin-1'))
                 ).decode('latin-1')
        eax_1 = str('0') + str(eax_1[1])
        eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        if str('00') not in str(eax_2):
            t = False
    A = 0
    eax = 'push   $%s' % (str(eax))
    if '-' in eax_2:
        A = 1
        eax_2 = eax_2.replace('-', '')
        eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
            eax_2, eax_1)
    if A == 0:
        eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
                                                                eax_1)
    shellcode = shellcode.replace('push   $0x5\npop    %eax', eax_add)
    t = True
    eax = str('0x4')
    while t:
        eax_1 = (binascii.b2a_hex((''.join(random.choice(
            chars) for i in range(1))).encode('latin-1'))
                 ).decode('latin-1')
        eax_1 = str('0') + str(eax_1[1])
        eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        if str('00') not in str(eax_2):
            t = False
    A = 0
    eax = 'push   $%s' % (str(eax))
    if '-' in eax_2:
        A = 1
        eax_2 = eax_2.replace('-', '')
        eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
            eax_2, eax_1)
    if A == 0:
        eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
                                                                eax_1)
    shellcode = shellcode.replace('push   $0x4\npop    %eax', eax_add)
    A = 0

    for line in shellcode.rsplit('\n'):
        if 'mov    %esp,%ebx' in line:
            A = 1
            shellcode = shellcode.replace(
                line, '\nmov    %esp,%ebx\n_z3r0d4y_\n')
        if A == 0:
            if 'push' in line and '$0x' in line and ',' not in line and len(
                    line) > 14:
                data = line.rsplit('push')[1].rsplit('$0x')[1]
                t = True
                while t:
                    ebx_1 = (binascii.b2a_hex((''.join(random.choice(
                        chars) for i in range(4))).encode('latin-1'))
                             ).decode('latin-1')
                    ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))
                    if str('00') not in str(ebx_1) and str('00') not in str(
                            ebx_2) and len(ebx_2) >= 7 and len(
                        ebx_1) >= 7 and '-' not in ebx_1 and ebx_1 != data:
                        if '-' in ebx_2:
                            ebx_2 = ebx_2.replace('-', '')
                            command = '\npush $0x%s\npop %ebx\nneg %ebx\nadd $0x%s,%ebx\npush %ebx\n' % (
                                str(ebx_2), str(ebx_1))
                            shellcode = shellcode.replace(line, command)
                            t = False
                        if t == True:
                            command = '\npush $0x%s\npop %ebx\nadd $0x%s,%ebx\npush %ebx\n' % (
                                str(ebx_2), str(ebx_1))
                            shellcode = shellcode.replace(line, command)
                            t = False
    shellcode = shellcode.replace('_z3r0d4y_', '')
    t = True
    eax = str('4014141')
    while t:
        eax_1 = (binascii.b2a_hex((''.join(random.choice(
            chars) for i in range(4))).encode('latin-1'))
                 ).decode('latin-1')
        eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        if eax_1 != eax:
            if eax > eax_1:
                if '00' not in str(eax_1) and '00' not in str(eax_2):
                    t = False
    A = 0
    eax = 'push   $%s' % (str(eax))
    if '-' in eax_2:
        A = 1
        eax_2 = eax_2.replace('-', '')
        eax_add = 'push $0x%s\npop %ecx\nneg %ecx\nadd $0x%s,%ecx\n' % (
            eax_2, eax_1)
    if A == 0:
        eax_add = 'push $0x%s\npop %ecx\nadd $0x%s,%ecx\n' % (eax_2,
                                                                eax_1)
    shellcode = shellcode.replace('push   $0x4014141\npop    %ecx',
                                  eax_add + '\n_z3r0d4y_\n').replace(
        'mov %esp,%ecx',
        '\n_z3r0|d4y_\nmov %esp,%ecx\n')
    A = 1
    for line in shellcode.rsplit('\n'):
        if str('_z3r0d4y_') in str(line):
            A = 0
        if str('_z3r0|d4y_') in str(line):
            A = 2
        if A == 0:
            if 'push' in line and '$0x' in line and ',' not in line and int(
                    len(line)) > 14:
                data = line.rsplit('push')[1].rsplit('$0x')[1]
                t = True
                while t:
                    ebx_1 = (binascii.b2a_hex((''.join(random.choice(
                        chars) for i in range(4))).encode('latin-1'))
                             ).decode('latin-1')
                    ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))
                    if ebx_1 != data and str('00') not in str(
                            ebx_1) and str('00') not in str(ebx_2) and int(
                        len(ebx_2)) >= 7 and int(len(
                        ebx_1)) >= 7 and '-' not in ebx_1:
                        if '-' in ebx_2:
                            ebx_2 = ebx_2.replace('-', '')
                            if int(len(ebx_2)) == 7:
                                ebx_2 = str('0') + str(ebx_2)
                            command = '\npush $0x%s\npop %ecx\nneg %ecx\nadd $0x%s,%ecx\npush %ecx\n' % (
                                str(ebx_2), str(ebx_1))
                            shellcode = shellcode.replace(line, command)
                            t = False
                        if '-' not in ebx_2 and t == True:
                            if int(len(ebx_2)) == 7:
                                ebx_2 = str('0') + str(ebx_2)
                            command = '\npush $0x%s\npop %ecx\nadd $0x%s,%ecx\npush %ecx\n' % (
                                str(ebx_2), str(ebx_1))
                            shellcode = shellcode.replace(line, command)
                            t = False
        if A == 2:
            if 'push' in line and '$0x' in line and ',' not in line and int(
                    len(line)) > 14:
                data = line.rsplit('push')[1].rsplit('$0x')[1]
                t = True
                while t:
                    ebx_1 = (
                        binascii.b2a_hex((''.join(random.choice(chars) for i in range(4))).encode('latin-1'))).decode(
                        'latin-1')
                    ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))
                    if ebx_1 != data and str('00') not in str(
                            ebx_1) and str('00') not in str(ebx_2) and int(
                        len(ebx_2)) >= 7 and int(len(
                        ebx_1)) >= 7 and '-' not in ebx_1:
                        if '-' in ebx_2:
                            ebx_2 = ebx_2.replace('-', '')
                            if int(len(ebx_2)) == 7:
                                ebx_2 = str('0') + str(ebx_2)
                            command = '\npush $0x%s\npop %edx\nneg %edx\nadd $0x%s,%edx\npush %edx\n' % (
                                str(ebx_2), str(ebx_1))
                            shellcode = shellcode.replace(line, command)
                            t = False
                        if '-' not in ebx_2 and t == True:
                            if int(len(ebx_2)) == 7:
                                ebx_2 = str('0') + str(ebx_2)
                            command = '\npush $0x%s\npop %edx\nadd $0x%s,%edx\npush %edx\n' % (
                                str(ebx_2), str(ebx_1))
                            shellcode = shellcode.replace(line, command)
                            t = False
    shellcode = shellcode.replace('_z3r0d4y_', '').replace('_z3r0|d4y_',
                                                           '')
    t = True
    eax = str('0b909090')
    while t:
        eax_1 = (binascii.b2a_hex((''.join(random.choice(chars) for i in range(4))).encode('latin-1'))).decode(
            'latin-1')
        eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        if '00' not in str(eax_1) and '00' not in str(
                eax_2) and eax_1 != eax:
            t = False
    A = 0
    eax = 'push   $%s' % (str(eax))
    if '-' in eax_2:
        A = 1
        eax_2 = eax_2.replace('-', '')
        eax_add = 'push $0x%s\npop %edx\nneg %edx\nadd $0x%s,%edx\n' % (
            eax_2, eax_1)
    if A == 0:
        eax_add = 'push $0x%s\npop %edx\nadd $0x%s,%edx\n' % (eax_2,
                                                                eax_1)
    shellcode = shellcode.replace('push $0x0b909090\n\npop %edx\n',
                                  eax_add)


def start(shellcode, job):
    if job == 'chmod':
        # t = True
        # eax = str('0x0f')
        # while t:
        #     eax_1 = (binascii.b2a_hex((''.join(random.choice(chars) for i in range(1))).encode('latin-1'))).decode('latin-1')
        #     eax_1 = str('0') + str(eax_1[1])
        #     eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        #     if eax > eax_1:
        #         if '00' not in str(eax_1) and '00' not in str(eax_2):
        #             t = False
        # eax = 'push   $%s' % (str(eax))
        # eax_add = f'push $0x{eax_1}\npop %eax\npush $0x{eax_2}\npop %ebx\nadd %eax,%ebx\npush %ebx\n'
        # shellcode = shellcode.replace(eax, eax_add)
        # ebx = str(shellcode.rsplit('\n')[8])
        # ebx_value = str(shellcode.rsplit('\n')[8].rsplit()[1][1:])
        # t = True
        # while t:
        #     ebx_1 = (binascii.b2a_hex((''.join(random.choice(chars) for i in range(4))).encode('latin-1'))).decode('latin-1')
        #     ebx_2 = "%x" % (int(ebx_value, 16) - int(ebx_1, 16))
        #     if '00' not in str(ebx_1) and '00' not in str(ebx_2) and int(len(
        #             ebx_1)) >= 7 and int(len(ebx_2)) >= 7 and '-' in ebx_2:
        #         t = False
        # ebx_2 = ebx_2.replace('-', '')
        # ebx_add = 'push $0x%s\npop %ebx\npush $0x%s\npop %ecx\nneg %ecx\nadd %ecx,%ebx\npush %ebx\n_z3r0d4y_\n' % (
        #     str(ebx_1), str(ebx_2))
        # shellcode = shellcode.replace(ebx, ebx_add)
        # n = 0
        # start = ''
        # middle = ''
        # end = ''
        # add = 0
        # for l in shellcode.rsplit('\n'):
        #     n += 1
        #     if add == 0:
        #         if '_z3r0d4y_' not in l:
        #             start += l + '\n'
        #         else:
        #             add = 1
        #     if add == 1:
        #         if '_z3r0d4y_' not in l:
        #             if '%esp,%ebx' not in l:
        #                 middle += l + '\n'
        #             else:
        #                 add = 2
        #     if add == 2:
        #         end += l + '\n'
        # for l in middle.rsplit('\n'):
        #     t = True
        #     while t:
        #         if 'push $0x' in l:
        #             edx = l.rsplit()[1][1:]
        #             edx_1 = (binascii.b2a_hex((''.join(random.choice(
        #                 chars) for i in range(4))).encode('latin-1'))
        #                      ).decode('latin-1')
        #             edx_2 = "%x" % (int(edx[2:], 16) - int(edx_1, 16))
        #             if '00' not in str(edx_1) and '00' not in str(
        #                     edx_2) and '-' in edx_2 and int(len(
        #                         edx_2)) >= 7 and int(len(
        #                             edx_1)) >= 7 and '-' not in edx_1:
        #                 edx_2 = edx_2.replace('-', '')
        #                 command = '\npush $0x%s\npop %ebx\npush $0x%s\npop %edx\nneg %edx\nadd %ebx,%edx\npush %edx\n' % (
        #                     str(edx_1), str(edx_2))
        #                 middle = middle.replace(l, command)
        #                 t = False
        #         else:
        #             t = False
        # shellcode = start + middle + end
        pass
    elif 'dir_create' == job:
        # shellcode = 'xor %edx,%edx\n' + shellcode.replace(
        #     'push   $0xb\npop    %eax\ncltd',
        #     '').replace('push   %ebx\nmov    %esp,%ecx',
        #                 'push   %ebx\nmov    %esp,%ecx' + '\n' +
        #                 'push   $0xb\npop    %eax\ncltd')
        # t = True
        # eax = str('0xb')
        # while t:
        #     eax_1 = (binascii.b2a_hex((''.join(random.choice(
        #         chars) for i in range(1))).encode('latin-1'))
        #              ).decode('latin-1')
        #     eax_1 = str('0') + str(eax_1[1])
        #     eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        #     if eax > eax_1:
        #         if '00' not in str(eax_1) and '00' not in str(eax_2):
        #             t = False
        # A = 0
        # eax = 'push   $%s' % (str(eax))
        # if '-' in eax_2:
        #     A = 1
        #     eax_2 = eax_2.replace('-', '')
        #     eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
        #         eax_2, eax_1)
        #
        # if A == 0:
        #     eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
        #                                                             eax_1)
        # shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',
        #                               eax_add + '\ncltd\n')
        # for line in shellcode.rsplit('\n'):
        #     if 'push' in line and '$0x' in line and ',' not in line and len(
        #             line) > 14:
        #         data = line.rsplit('push')[1].rsplit('$0x')[1]
        #         t = True
        #         while t:
        #             ebx_1 = (binascii.b2a_hex((''.join(random.choice(
        #                 chars) for i in range(4))).encode('latin-1'))
        #                      ).decode('latin-1')
        #             ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))
        #
        #             if str('00') not in str(ebx_1) and str('00') not in str(
        #                     ebx_2) and '-' in ebx_2 and len(
        #                         ebx_2) >= 7 and len(
        #                             ebx_1) >= 7 and '-' not in ebx_1:
        #                 ebx_2 = ebx_2.replace('-', '')
        #                 command = '\npush $0x%s\npop %ebx\npush $0x%s\npop %eax\nneg %eax\nadd %ebx,%eax\npush %eax\n' % (
        #                     str(ebx_1), str(ebx_2))
        #                 shellcode = shellcode.replace(line, command)
        #                 t = False
        pass
    elif 'download_execute' == job:
        # shellcode = 'xor %edx,%edx\n' + shellcode.replace(
        #     'push   $0xb\npop    %eax\ncltd',
        #     '').replace('push   %ebx\nmov    %esp,%ecx',
        #                 'push   %ebx\nmov    %esp,%ecx' + '\n' +
        #                 'push   $0xb\npop    %eax\ncltd')
        # t = True
        # eax = str('0xb')
        # while t:
        #     eax_1 = (binascii.b2a_hex((''.join(random.choice(
        #         chars) for i in range(1))).encode('latin-1'))
        #              ).decode('latin-1')
        #     eax_1 = str('0') + str(eax_1[1])
        #     eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        #     if eax > eax_1:
        #         if '00' not in str(eax_1) and '00' not in str(eax_2):
        #             t = False
        # A = 0
        # eax = 'push   $%s' % (str(eax))
        # if '-' in eax_2:
        #     A = 1
        #     eax_2 = eax_2.replace('-', '')
        #     eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
        #         eax_2, eax_1)
        #
        # if A == 0:
        #     eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
        #                                                             eax_1)
        # shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',
        #                               eax_add + '\ncltd\n')
        # for line in shellcode.rsplit('\n'):
        #     if 'push' in line and '$0x' in line and ',' not in line and len(
        #             line) > 14:
        #         data = line.rsplit('push')[1].rsplit('$0x')[1]
        #         t = True
        #         while t:
        #             ebx_1 = (binascii.b2a_hex((''.join(random.choice(
        #                 chars) for i in range(4))).encode('latin-1'))
        #                      ).decode('latin-1')
        #             ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))
        #
        #             if str('00') not in str(ebx_1) and str('00') not in str(
        #                     ebx_2) and '-' in ebx_2 and len(
        #                         ebx_2) >= 7 and len(
        #                             ebx_1) >= 7 and '-' not in ebx_1:
        #                 ebx_2 = ebx_2.replace('-', '')
        #                 command = '\npush $0x%s\npop %ebx\npush $0x%s\npop %eax\nneg %eax\nadd %ebx,%eax\npush %eax\n' % (
        #                     str(ebx_1), str(ebx_2))
        #                 shellcode = shellcode.replace(line, command)
        #                 t = False
        pass
    elif 'download' == job:
        # shellcode = 'xor %edx,%edx\n' + shellcode.replace(
        #     'push   $0xb\npop    %eax\ncltd',
        #     '').replace('push   %ebx\nmov    %esp,%ecx',
        #                 'push   %ebx\nmov    %esp,%ecx' + '\n' +
        #                 'push   $0xb\npop    %eax\ncltd')
        # t = True
        # eax = str('0xb')
        # while t:
        #     eax_1 = (binascii.b2a_hex((''.join(random.choice(
        #         chars) for i in range(1))).encode('latin-1'))
        #              ).decode('latin-1')
        #     eax_1 = str('0') + str(eax_1[1])
        #     eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        #     if eax > eax_1:
        #         if '00' not in str(eax_1) and '00' not in str(eax_2):
        #             t = False
        # A = 0
        # eax = 'push   $%s' % (str(eax))
        # if '-' in eax_2:
        #     A = 1
        #     eax_2 = eax_2.replace('-', '')
        #     eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
        #         eax_2, eax_1)
        #
        # if A == 0:
        #     eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
        #                                                             eax_1)
        # shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',
        #                               eax_add + '\ncltd\n')
        # for line in shellcode.rsplit('\n'):
        #     if 'push' in line and '$0x' in line and ',' not in line and len(
        #             line) > 14:
        #         data = line.rsplit('push')[1].rsplit('$0x')[1]
        #         t = True
        #         while t:
        #             ebx_1 = (binascii.b2a_hex((''.join(random.choice(
        #                 chars) for i in range(4))).encode('latin-1'))
        #                      ).decode('latin-1')
        #             ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))
        #
        #             if str('00') not in str(ebx_1) and str('00') not in str(
        #                     ebx_2) and '-' in ebx_2 and len(
        #                         ebx_2) >= 7 and len(
        #                             ebx_1) >= 7 and '-' not in ebx_1:
        #                 ebx_2 = ebx_2.replace('-', '')
        #                 command = '\npush $0x%s\npop %ebx\npush $0x%s\npop %eax\nneg %eax\nadd %ebx,%eax\npush %eax\n' % (
        #                     str(ebx_1), str(ebx_2))
        #                 shellcode = shellcode.replace(line, command)
        #                 t = False
        pass
    elif 'exec' == job:
        # t = True
        # eax = str('0x46')
        # while t:
        #     eax_1 = (binascii.b2a_hex((''.join(random.choice(
        #         chars) for i in range(1))).encode('latin-1'))
        #              ).decode('latin-1')
        #     eax_1 = str('0') + str(eax_1[1])
        #     eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        #     if eax > eax_1:
        #         if '00' not in str(eax_1) and '00' not in str(eax_2):
        #             t = False
        #
        # A = 0
        # eax = 'push   $%s' % (str(eax))
        # if '-' in eax_2:
        #     A = 1
        #     eax_2 = eax_2.replace('-', '')
        #     eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
        #         eax_2, eax_1)
        #
        # if A == 0:
        #     eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
        #                                                             eax_1)
        # shellcode = shellcode.replace('mov    $0x46,%al', eax_add)
        # for line in shellcode.rsplit('\n'):
        #     if 'push' in line and '$0x' in line and ',' not in line and len(
        #             line) > 14:
        #         data = line.rsplit('push')[1].rsplit('$0x')[1]
        #         t = True
        #         while t:
        #             ebx_1 = (binascii.b2a_hex((''.join(random.choice(
        #                 chars) for i in range(4))).encode('latin-1'))
        #                      ).decode('latin-1')
        #             ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))
        #             if str('00') not in str(ebx_1) and str('00') not in str(
        #                     ebx_2) and '-' in ebx_2 and len(ebx_2.replace(
        #                         '-', '')) >= 7 and len(
        #                             ebx_1) >= 7 and '-' not in ebx_1:
        #                 ebx_2 = ebx_2.replace('-', '')
        #                 command = '\npush $0x%s\npop %ebx\npush $0x%s\npop %eax\nneg %eax\nadd %ebx,%eax\npush %eax\n' % (
        #                     str(ebx_1), str(ebx_2))
        #                 shellcode = shellcode.replace(line, command)
        #                 t = False
        pass
    elif 'file_create' == job:
        # shellcode = 'xor %edx,%edx\n' + shellcode.replace(
        #     'push   $0xb\npop    %eax\ncltd',
        #     '').replace('push   %ebx\nmov    %esp,%ecx',
        #                 'push   %ebx\nmov    %esp,%ecx' + '\n' +
        #                 'push   $0xb\npop    %eax\ncltd')
        # t = True
        # eax = str('0xb')
        # while t:
        #     eax_1 = (binascii.b2a_hex((''.join(random.choice(
        #         chars) for i in range(1))).encode('latin-1'))
        #              ).decode('latin-1')
        #     eax_1 = str('0') + str(eax_1[1])
        #     eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        #     if eax > eax_1:
        #         if '00' not in str(eax_1) and '00' not in str(eax_2):
        #             t = False
        # A = 0
        # eax = 'push   $%s' % (str(eax))
        # if '-' in eax_2:
        #     A = 1
        #     eax_2 = eax_2.replace('-', '')
        #     eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
        #         eax_2, eax_1)
        #
        # if A == 0:
        #     eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
        #                                                             eax_1)
        # shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',
        #                               eax_add + '\ncltd\n')
        # for line in shellcode.rsplit('\n'):
        #     if 'push' in line and '$0x' in line and ',' not in line and len(
        #             line) > 14:
        #         data = line.rsplit('push')[1].rsplit('$0x')[1]
        #         t = True
        #         while t:
        #             ebx_1 = (binascii.b2a_hex((''.join(random.choice(
        #                 chars) for i in range(4))).encode('latin-1'))
        #                      ).decode('latin-1')
        #             ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))
        #
        #             if str('00') not in str(ebx_1) and str('00') not in str(
        #                     ebx_2) and '-' in ebx_2 and len(
        #                         ebx_2) >= 7 and len(
        #                             ebx_1) >= 7 and '-' not in ebx_1:
        #                 ebx_2 = ebx_2.replace('-', '')
        #                 command = '\npush $0x%s\npop %ebx\npush $0x%s\npop %eax\nneg %eax\nadd %ebx,%eax\npush %eax\n' % (
        #                     str(ebx_1), str(ebx_2))
        #                 shellcode = shellcode.replace(line, command)
        #                 t = False
        pass
    elif 'script_executor' == job:
        # shellcode = 'xor %edx,%edx\n' + shellcode.replace(
        #     'push   $0xb\npop    %eax\ncltd',
        #     '').replace('push   %ebx\nmov    %esp,%ecx',
        #                 'push   %ebx\nmov    %esp,%ecx' + '\n' +
        #                 'push   $0xb\npop    %eax\ncltd')
        # t = True
        # eax = str('0xb')
        # while t:
        #     eax_1 = (binascii.b2a_hex((''.join(random.choice(
        #         chars) for i in range(1))).encode('latin-1'))
        #              ).decode('latin-1')
        #     eax_1 = str('0') + str(eax_1[1])
        #     eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        #     if eax > eax_1:
        #         if '00' not in str(eax_1) and '0' not in str(eax_2):
        #             t = False
        # A = 0
        # eax = 'push   $%s' % (str(eax))
        # if '-' in eax_2:
        #     A = 1
        #     eax_2 = eax_2.replace('-', '')
        #     eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
        #         eax_2, eax_1)
        #
        # if A == 0:
        #     eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
        #                                                             eax_1)
        # shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',
        #                               eax_add + '\ncltd\n')
        # for line in shellcode.rsplit('\n'):
        #     if 'push' in line and '$0x' in line and ',' not in line and len(
        #             line) > 14:
        #         data = line.rsplit('push')[1].rsplit('$0x')[1]
        #         t = True
        #         while t:
        #             ebx_1 = (binascii.b2a_hex((''.join(random.choice(
        #                 chars) for i in range(4))).encode('latin-1'))
        #                      ).decode('latin-1')
        #             ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))
        #
        #             if str('00') not in str(ebx_1) and str('00') not in str(
        #                     ebx_2) and '-' in ebx_2 and len(
        #                         ebx_2) >= 7 and len(
        #                             ebx_1) >= 7 and '-' not in ebx_1:
        #                 ebx_2 = ebx_2.replace('-', '')
        #                 command = '\npush $0x%s\npop %ebx\npush $0x%s\npop %eax\nneg %eax\nadd %ebx,%eax\npush %eax\n' % (
        #                     str(ebx_1), str(ebx_2))
        #                 shellcode = shellcode.replace(line, command)
        #                 t = False
        pass
    elif 'system' == job:
        # shellcode = 'xor %edx,%edx\n' + shellcode.replace(
        #     'push   $0xb\npop    %eax\ncltd',
        #     '').replace('push   %ebx\nmov    %esp,%ecx',
        #                 'push   %ebx\nmov    %esp,%ecx' + '\n' +
        #                 'push   $0xb\npop    %eax\ncltd')
        # t = True
        # eax = str('0xb')
        # while t:
        #     eax_1 = (binascii.b2a_hex((''.join(random.choice(
        #         chars) for i in range(1))).encode('latin-1'))
        #              ).decode('latin-1')
        #     eax_1 = str('0') + str(eax_1[1])
        #     eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        #     if eax > eax_1:
        #         if '00' not in str(eax_1) and '0' not in str(eax_2):
        #             t = False
        # A = 0
        # eax = 'push   $%s' % (str(eax))
        # if '-' in eax_2:
        #     A = 1
        #     eax_2 = eax_2.replace('-', '')
        #     eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
        #         eax_2, eax_1)
        # if A == 0:
        #     eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
        #                                                             eax_1)
        # shellcode = shellcode.replace('push   $0xb\npop    %eax\ncltd',
        #                               eax_add + '\ncltd\n')
        # for line in shellcode.rsplit('\n'):
        #     if 'push' in line and '$0x' in line and ',' not in line and len(
        #             line) > 14:
        #         data = line.rsplit('push')[1].rsplit('$0x')[1]
        #         t = True
        #         while t:
        #             ebx_1 = (binascii.b2a_hex((''.join(random.choice(
        #                 chars) for i in range(4))).encode('latin-1'))
        #                      ).decode('latin-1')
        #             ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))
        #
        #             if str('00') not in str(ebx_1) and str('00') not in str(
        #                     ebx_2) and '-' in ebx_2 and len(
        #                         ebx_2) >= 7 and len(
        #                             ebx_1) >= 7 and '-' not in ebx_1:
        #                 ebx_2 = ebx_2.replace('-', '')
        #                 command = '\npush $0x%s\npop %ebx\npush $0x%s\npop %eax\nneg %eax\nadd %ebx,%eax\npush %eax\n' % (
        #                     str(ebx_1), str(ebx_2))
        #                 shellcode = shellcode.replace(line, command)
        #                 t = False
        pass
    elif 'write' == job:
        # t = True
        # eax = str('0x5')
        # while t:
        #     eax_1 = (binascii.b2a_hex((''.join(random.choice(
        #         chars) for i in range(1))).encode('latin-1'))
        #              ).decode('latin-1')
        #     eax_1 = str('0') + str(eax_1[1])
        #     eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        #     if str('00') not in str(eax_2):
        #         t = False
        # A = 0
        # eax = 'push   $%s' % (str(eax))
        # if '-' in eax_2:
        #     A = 1
        #     eax_2 = eax_2.replace('-', '')
        #     eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
        #         eax_2, eax_1)
        # if A == 0:
        #     eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
        #                                                             eax_1)
        # shellcode = shellcode.replace('push   $0x5\npop    %eax', eax_add)
        # t = True
        # eax = str('0x4')
        # while t:
        #     eax_1 = (binascii.b2a_hex((''.join(random.choice(
        #         chars) for i in range(1))).encode('latin-1'))
        #              ).decode('latin-1')
        #     eax_1 = str('0') + str(eax_1[1])
        #     eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        #     if str('00') not in str(eax_2):
        #         t = False
        # A = 0
        # eax = 'push   $%s' % (str(eax))
        # if '-' in eax_2:
        #     A = 1
        #     eax_2 = eax_2.replace('-', '')
        #     eax_add = 'push $0x%s\npop %eax\nneg %eax\nadd $0x%s,%eax\n' % (
        #         eax_2, eax_1)
        # if A == 0:
        #     eax_add = 'push $0x%s\npop %eax\nadd $0x%s,%eax\n' % (eax_2,
        #                                                             eax_1)
        # shellcode = shellcode.replace('push   $0x4\npop    %eax', eax_add)
        # A = 0
        #
        # for line in shellcode.rsplit('\n'):
        #     if 'mov    %esp,%ebx' in line:
        #         A = 1
        #         shellcode = shellcode.replace(
        #             line, '\nmov    %esp,%ebx\n_z3r0d4y_\n')
        #     if A == 0:
        #         if 'push' in line and '$0x' in line and ',' not in line and len(
        #                 line) > 14:
        #             data = line.rsplit('push')[1].rsplit('$0x')[1]
        #             t = True
        #             while t:
        #                 ebx_1 = (binascii.b2a_hex((''.join(random.choice(
        #                     chars) for i in range(4))).encode('latin-1'))
        #                          ).decode('latin-1')
        #                 ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))
        #                 if str('00') not in str(ebx_1) and str('00') not in str(
        #                         ebx_2) and len(ebx_2) >= 7 and len(
        #                             ebx_1) >= 7 and '-' not in ebx_1 and ebx_1 != data:
        #                     if '-' in ebx_2:
        #                         ebx_2 = ebx_2.replace('-', '')
        #                         command = '\npush $0x%s\npop %ebx\nneg %ebx\nadd $0x%s,%ebx\npush %ebx\n' % (
        #                             str(ebx_2), str(ebx_1))
        #                         shellcode = shellcode.replace(line, command)
        #                         t = False
        #                     if t == True:
        #                         command = '\npush $0x%s\npop %ebx\nadd $0x%s,%ebx\npush %ebx\n' % (
        #                             str(ebx_2), str(ebx_1))
        #                         shellcode = shellcode.replace(line, command)
        #                         t = False
        # shellcode = shellcode.replace('_z3r0d4y_', '')
        # t = True
        # eax = str('4014141')
        # while t:
        #     eax_1 = (binascii.b2a_hex((''.join(random.choice(
        #         chars) for i in range(4))).encode('latin-1'))
        #              ).decode('latin-1')
        #     eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        #     if eax_1 != eax:
        #         if eax > eax_1:
        #             if '00' not in str(eax_1) and '00' not in str(eax_2):
        #                 t = False
        # A = 0
        # eax = 'push   $%s' % (str(eax))
        # if '-' in eax_2:
        #     A = 1
        #     eax_2 = eax_2.replace('-', '')
        #     eax_add = 'push $0x%s\npop %ecx\nneg %ecx\nadd $0x%s,%ecx\n' % (
        #         eax_2, eax_1)
        # if A == 0:
        #     eax_add = 'push $0x%s\npop %ecx\nadd $0x%s,%ecx\n' % (eax_2,
        #                                                             eax_1)
        # shellcode = shellcode.replace('push   $0x4014141\npop    %ecx',
        #                               eax_add + '\n_z3r0d4y_\n').replace(
        #                                   'mov %esp,%ecx',
        #                                   '\n_z3r0|d4y_\nmov %esp,%ecx\n')
        # A = 1
        # for line in shellcode.rsplit('\n'):
        #     if str('_z3r0d4y_') in str(line):
        #         A = 0
        #     if str('_z3r0|d4y_') in str(line):
        #         A = 2
        #     if A == 0:
        #         if 'push' in line and '$0x' in line and ',' not in line and int(
        #                 len(line)) > 14:
        #             data = line.rsplit('push')[1].rsplit('$0x')[1]
        #             t = True
        #             while t:
        #                 ebx_1 = (binascii.b2a_hex((''.join(random.choice(
        #                     chars) for i in range(4))).encode('latin-1'))
        #                          ).decode('latin-1')
        #                 ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))
        #                 if ebx_1 != data and str('00') not in str(
        #                         ebx_1) and str('00') not in str(ebx_2) and int(
        #                             len(ebx_2)) >= 7 and int(len(
        #                                 ebx_1)) >= 7 and '-' not in ebx_1:
        #                     if '-' in ebx_2:
        #                         ebx_2 = ebx_2.replace('-', '')
        #                         if int(len(ebx_2)) == 7:
        #                             ebx_2 = str('0') + str(ebx_2)
        #                         command = '\npush $0x%s\npop %ecx\nneg %ecx\nadd $0x%s,%ecx\npush %ecx\n' % (
        #                             str(ebx_2), str(ebx_1))
        #                         shellcode = shellcode.replace(line, command)
        #                         t = False
        #                     if '-' not in ebx_2 and t == True:
        #                         if int(len(ebx_2)) == 7:
        #                             ebx_2 = str('0') + str(ebx_2)
        #                         command = '\npush $0x%s\npop %ecx\nadd $0x%s,%ecx\npush %ecx\n' % (
        #                             str(ebx_2), str(ebx_1))
        #                         shellcode = shellcode.replace(line, command)
        #                         t = False
        #     if A == 2:
        #         if 'push' in line and '$0x' in line and ',' not in line and int(
        #                 len(line)) > 14:
        #             data = line.rsplit('push')[1].rsplit('$0x')[1]
        #             t = True
        #             while t:
        #                 ebx_1 = (binascii.b2a_hex((''.join(random.choice(chars) for i in range(4))).encode('latin-1'))).decode('latin-1')
        #                 ebx_2 = "%x" % (int(data, 16) - int(ebx_1, 16))
        #                 if ebx_1 != data and str('00') not in str(
        #                         ebx_1) and str('00') not in str(ebx_2) and int(
        #                             len(ebx_2)) >= 7 and int(len(
        #                                 ebx_1)) >= 7 and '-' not in ebx_1:
        #                     if '-' in ebx_2:
        #                         ebx_2 = ebx_2.replace('-', '')
        #                         if int(len(ebx_2)) == 7:
        #                             ebx_2 = str('0') + str(ebx_2)
        #                         command = '\npush $0x%s\npop %edx\nneg %edx\nadd $0x%s,%edx\npush %edx\n' % (
        #                             str(ebx_2), str(ebx_1))
        #                         shellcode = shellcode.replace(line, command)
        #                         t = False
        #                     if '-' not in ebx_2 and t == True:
        #                         if int(len(ebx_2)) == 7:
        #                             ebx_2 = str('0') + str(ebx_2)
        #                         command = '\npush $0x%s\npop %edx\nadd $0x%s,%edx\npush %edx\n' % (
        #                             str(ebx_2), str(ebx_1))
        #                         shellcode = shellcode.replace(line, command)
        #                         t = False
        # shellcode = shellcode.replace('_z3r0d4y_', '').replace('_z3r0|d4y_',
        #                                                        '')
        # t = True
        # eax = str('0b909090')
        # while t:
        #     eax_1 = (binascii.b2a_hex((''.join(random.choice(chars) for i in range(4))).encode('latin-1'))).decode('latin-1')
        #     eax_2 = "%x" % (int(eax, 16) - int(eax_1, 16))
        #     if '00' not in str(eax_1) and '00' not in str(
        #             eax_2) and eax_1 != eax:
        #         t = False
        # A = 0
        # eax = 'push   $%s' % (str(eax))
        # if '-' in eax_2:
        #     A = 1
        #     eax_2 = eax_2.replace('-', '')
        #     eax_add = 'push $0x%s\npop %edx\nneg %edx\nadd $0x%s,%edx\n' % (
        #         eax_2, eax_1)
        # if A == 0:
        #     eax_add = 'push $0x%s\npop %edx\nadd $0x%s,%edx\n' % (eax_2,
        #                                                             eax_1)
        # shellcode = shellcode.replace('push $0x0b909090\n\npop %edx\n',
        #                               eax_add)
        pass
    return shellcode

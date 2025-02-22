"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
from owasp_zsc.cores.compatible import *
from owasp_zsc.cores.alert import *
from owasp_zsc.cores import color
from owasp_zsc.cores.get_input import _input
from owasp_zsc.cores.file_out import downloaded_file_output
from urllib.request import urlopen
import html


def _html_decode(data):
    """HTML Decode function separate to handle py2 and py3."""
    return html.unescape(data)


def search_shellcode(cli, keyword):
    url = 'http://shell-storm.org/api/?s='
    if cli == True:
        pass
    else:
        keyword = _input('%skeyword_to_search%s' %
                         (color.color('blue'), color.color('yellow')), 'any', True)
    keyword = keyword.replace(' ', '*')
    try:
        data = urlopen(url + keyword).read()
        data = data.decode('utf-8')
    except:
        warn('connection error')
        return
    for shellcode_ in data.rsplit('\n'):
        try:
            shellcode_ = shellcode_.rsplit('::::')
            info('author: %s\tshellcode_id: %s\tplatform: %s\ttitle: %s\n' %
                 (shellcode_[0], shellcode_[3], shellcode_[1], shellcode_[2]))
        except:
            pass
    write('\n')


def download_shellcode(cli, shellcode_id, name):
    if cli == True:
        pass
    else:
        shellcode_id = _input('%sshellcode_id%s' %
                              (color.color('blue'), color.color('yellow')), 'int', True)
    url = 'http://shell-storm.org/shellcode/files/shellcode-%s.php' % (str(shellcode_id))
    try:
        data = urlopen(url).read().decode('utf-8').rsplit('<pre>')[1].rsplit('<body>')[0]
    except:
        warn('connection error\n')
        return

    write(_html_decode(data) + '\n\n')

    if cli == False:
        file_or_not = _input('Shellcode output to a .c file?(y or n)', 'any', True)
        if file_or_not[0] == 'y':
            target = _input('Target .c file?', 'any', True)
            downloaded_file_output(target, _html_decode(data))
    else:
        if name != '':
            downloaded_file_output(name, _html_decode(data))


def grab_all():
    url = 'http://shell-storm.org/shellcode/'
    try:
        data = urlopen(url).read().decode('utf-8').rsplit('\n')
    except:
        warn('connection error\n')
        return
    for shellcode in data:
        if '/shellcode/files/shellcode-' in shellcode:
            shellcode_id = shellcode.rsplit('<li><a href="/shellcode/files/shellcode-')[1].rsplit('.php')[0]
            title = shellcode.rsplit('">')[1].rsplit('</a>')[0]
            author = shellcode.rsplit('<i>')[1].rsplit('</i>')[0]
            info('id: ' + shellcode_id + ' - ' + title + ' ' + author + '\n')

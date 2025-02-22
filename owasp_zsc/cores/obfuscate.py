"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
from owasp_zsc.cores.alert import *


def obf_code(lang, encode, filename, content, cli):
    content = content.decode('utf-8')
    start = getattr(
        __import__('libs.encoders.%s.%s' % (lang, encode),
                   fromlist=['start']),
        'start')  # import endoing module
    content = start(content, cli)  # encoded content as returned value
    content = bytes(content, 'utf-8')
    f = open(filename, 'wb')  # writing content
    f.write(content)
    f.close()
    info('file "%s" encoded successfully!\n' % filename)
    return

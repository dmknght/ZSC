"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
"""
# bug fix reported by John Babio in version 1.0.4 johndbabio/[at]/gmail/./com


def color(user_color):
    if user_color == 'reset':
        return '\033[0m'
    if user_color == 'grey':
        return '\033[1;30m'
    if user_color == 'red':
        return '\033[1;31m'
    if user_color == 'green':
        return '\033[1;32m'
    if user_color == 'yellow':
        return '\033[1;33m'
    if user_color == 'blue':
        return '\033[1;34m'
    if user_color == 'purple':
        return '\033[1;35m'
    if user_color == 'cyan':
        return '\033[1;36m'
    if user_color == 'white':
        return '\033[1;37m'
    else:
        return ''

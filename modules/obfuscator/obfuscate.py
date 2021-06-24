from new_cores import base_module


class Module(base_module.BaseModule):
    file_dest = base_module.OptString("", "File to obfuscate")
    file_type = base_module.OptString("", "Type of obfuscate file")
    obf_method = base_module.OptString("", "Obfuscate method")

    def run(self):
        print(self.file_dest)
        print(self.file_dest.__dir__())

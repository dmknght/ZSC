from owasp_zsc.new_cores import base_module, alert


class Module(base_module.BaseModule):
    file = base_module.OptString("", "File to obfuscate")
    type = base_module.OptString("", "Type of obfuscate file")

    def run(self):
        if not self.file:
            alert.error("File option is required")
            return
        if not self.method:
            alert.error("An obfuscation method is required\n")
            return
        from owasp_zsc.libs import obfuscate
        import importlib
        try:
            import traceback
            module_path = obfuscate.__path__[0].split("owasp_zsc")[1].replace("/", ".")
            module = importlib.import_module(f"owasp_zsc{module_path}.{self.type}.{self.method}")
            alert.info("Getting file content")
            content = open(self.file).read()
            alert.info("Obfuscating file content")
            obfuscated_content = getattr(module, "start")(content, self.encode_times)
            alert.info("Generating obfuscated script")
            f = open(self.file, "w")
            f.write(obfuscated_content)
            f.close()
            alert.info("Completed. Your file is obfuscated.")
        except AttributeError:
            alert.error("Invalid module\n")
        except:
            traceback.print_exc()

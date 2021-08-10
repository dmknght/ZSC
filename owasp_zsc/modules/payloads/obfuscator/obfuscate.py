import traceback
from owasp_zsc.new_cores import base_module, alert


class Module(base_module.BaseModule):
    file = base_module.OptString("", "File to obfuscate")
    type = base_module.OptString("", "File type")

    def run(self):
        if not self.file:
            alert.error("File option is required")
            return
        if not self.method:
            alert.error("An obfuscation method is required")
            return
        from owasp_zsc.libs import obfuscate
        import importlib
        try:
            module_path = obfuscate.__path__[0].split("owasp_zsc")[1].replace("/", ".")
            module = importlib.import_module(f"owasp_zsc{module_path}.{self.type}.{self.method}")
            module = getattr(module, "ObfuscateModule")()
            if hasattr(module, "times"):
                setattr(module, "times", self.times)  # FIX submodule doesn't take new times from options

            alert.info("Getting file content")
            content = open(self.file).read()
            if not content.strip():
                alert.error("File is empty!")
                return

            alert.info("Obfuscating file content")
            obfuscated_content = module.start(content)

            alert.info("Generating obfuscated script")
            f = open(self.file, "w")
            f.write(obfuscated_content)
            f.close()

            alert.info("Completed. Your file is obfuscated.")
        except AttributeError:
            traceback.print_exc()
            alert.error("Invalid module")
        except:
            traceback.print_exc()

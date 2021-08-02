# from base64 import b64encode
from owasp_zsc.new_cores.base_module import BaseModule


class Encoder(BaseModule):
    # test_value = OptString("", "Target file to change permission")
    __info__ = {
        # "name": "Python Base64 Encoder",
        "description": "Add random encoding",
        "authors": (
            "Ali Razmjoo <ali.razmjoo@owasp.org>",  # routersploit module
        ),
    }

    def run(self, payload):
        pass
        # encoded_payload = str(b64encode(bytes(payload, "utf-8")), "utf-8")
        # return "exec('{}'.decode('base64'))".format(encoded_payload) # TODO fix exec by importlib

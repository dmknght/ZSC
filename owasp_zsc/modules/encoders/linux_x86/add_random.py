from base64 import b64encode
from owasp_zsc.new_cores.base_module import BaseEncoder


class Encoder(BaseEncoder):
    __info__ = {
        # "name": "Python Base64 Encoder",
        "description": "Add random encoding",
        "authors": (
            "Ali Razmjoo <ali.razmjoo@owasp.org>",  # routersploit module
        ),
    }

    def encode(self, payload):
        encoded_payload = str(b64encode(bytes(payload, "utf-8")), "utf-8")
        return "exec('{}'.decode('base64'))".format(encoded_payload)

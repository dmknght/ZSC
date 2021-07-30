from owasp_zsc.new_cores.base_module import BaseModule


class Encoder(BaseModule):
    __info__ = {
        "description": "Xor encode with random key",
        "authors": (
            "Ali Razmjoo <ali.razmjoo@owasp.org>",  # routersploit module
        ),
    }

    def encode(self, payload):

        return "done"
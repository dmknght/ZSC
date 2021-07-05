from owasp_zsc.new_cores.base_module import BaseEncoder


class Encoder(BaseEncoder):
    __info__ = {
        "description": "Xor encode with random key",
        "authors": (
            "Ali Razmjoo <ali.razmjoo@owasp.org>",  # routersploit module
        ),
    }

    def encode(self, payload):

        return "done"
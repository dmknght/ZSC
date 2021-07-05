from owasp_zsc.new_cores.base_module import BaseEncoder, OptString


class Encoder(BaseEncoder):
    key = OptString("test", "Test value for arguments")
    __info__ = {
        "description": "Xor encoder",
        "authors": (
            "Ali Razmjoo <ali.razmjoo@owasp.org>",  # routersploit extras
        ),
    }

    def encode(self, payload):
        return "done"
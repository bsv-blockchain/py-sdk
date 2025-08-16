"""bsv Python SDK package minimal initializer.

Avoid importing heavy submodules at package import time to prevent circular imports
and reduce side effects. Import submodules explicitly where needed, e.g.:
    from bsv.keys import PrivateKey
    from bsv.auth.peer import Peer
"""

__version__ = '1.0.7.1'

# Optionally expose convenient factories later if needed.
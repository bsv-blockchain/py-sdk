"""Deprecated: Arcade was renamed to BSV Broadcaster.

Use :mod:`bsv.broadcasters.bsv_broadcaster` (``BsvBroadcaster``,
``BsvBroadcasterConfig``). The names below remain as aliases so existing code
keeps working; constructing :class:`Arcade` or :class:`ArcadeConfig` emits a
:class:`DeprecationWarning`.
"""

import warnings

from .bsv_broadcaster import BSV_BROADCASTER_MINED_TX_STATUSES as ARCADE_MINED_TX_STATUSES
from .bsv_broadcaster import BSV_BROADCASTER_PROGRESSING_TX_STATUSES as ARCADE_PROGRESSING_TX_STATUSES
from .bsv_broadcaster import BSV_BROADCASTER_SEEN_TX_STATUSES as ARCADE_SEEN_TX_STATUSES
from .bsv_broadcaster import BSV_BROADCASTER_TERMINAL_FAILURE_TX_STATUSES as ARCADE_TERMINAL_FAILURE_TX_STATUSES
from .bsv_broadcaster import BsvBroadcaster, BsvBroadcasterConfig
from .bsv_broadcaster import bsv_broadcaster_post_data_indicates_failure as arcade_post_data_indicates_failure

__all__ = [
    "ARCADE_MINED_TX_STATUSES",
    "ARCADE_PROGRESSING_TX_STATUSES",
    "ARCADE_SEEN_TX_STATUSES",
    "ARCADE_TERMINAL_FAILURE_TX_STATUSES",
    "Arcade",
    "ArcadeConfig",
    "arcade_post_data_indicates_failure",
]


class ArcadeConfig(BsvBroadcasterConfig):
    """Deprecated alias of :class:`~bsv.broadcasters.bsv_broadcaster.BsvBroadcasterConfig`."""

    def __init__(self, *args, **kwargs):
        warnings.warn(
            "ArcadeConfig is deprecated. Use BsvBroadcasterConfig; Arcade was renamed to BSV Broadcaster.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)


class Arcade(BsvBroadcaster):
    """Deprecated alias of :class:`~bsv.broadcasters.bsv_broadcaster.BsvBroadcaster`."""

    def __init__(self, *args, **kwargs):
        warnings.warn(
            "Arcade is deprecated. Use BsvBroadcaster; Arcade was renamed to BSV Broadcaster.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(*args, **kwargs)

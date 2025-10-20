import pytest
from bsv.broadcasters.whatsonchain import WhatsOnChainBroadcaster
from bsv.constants import Network
from bsv.broadcaster import BroadcastResponse, BroadcastFailure


class TestWhatsOnChainBroadcast:
   def test_network_enum(self):
       # Initialize with Network enum
       broadcaster = WhatsOnChainBroadcaster(Network.MAINNET)
       assert broadcaster.URL == "https://api.whatsonchain.com/v1/bsv/main/tx/raw"

       broadcaster = WhatsOnChainBroadcaster(Network.TESTNET)
       assert broadcaster.URL == "https://api.whatsonchain.com/v1/bsv/test/tx/raw"

   def test_network_string(self):
       # Initialize with string (backward compatibility)
       broadcaster = WhatsOnChainBroadcaster("main")
       assert broadcaster.URL == "https://api.whatsonchain.com/v1/bsv/main/tx/raw"

       broadcaster = WhatsOnChainBroadcaster("test")
       assert broadcaster.URL == "https://api.whatsonchain.com/v1/bsv/test/tx/raw"

       broadcaster = WhatsOnChainBroadcaster("mainnet")
       assert broadcaster.URL == "https://api.whatsonchain.com/v1/bsv/main/tx/raw"

       broadcaster = WhatsOnChainBroadcaster("testnet")
       assert broadcaster.URL == "https://api.whatsonchain.com/v1/bsv/test/tx/raw"

   def test_invalid_network(self):
       # Test invalid network string
       with pytest.raises(ValueError, match="Invalid network string:"):
           WhatsOnChainBroadcaster("invalid_network")
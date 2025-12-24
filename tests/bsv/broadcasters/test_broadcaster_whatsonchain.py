import pytest
from bsv.broadcasters.whatsonchain import WhatsOnChainBroadcaster
from bsv.constants import Network
from bsv.broadcasters.broadcaster import BroadcastResponse, BroadcastFailure


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

   @pytest.mark.asyncio
   async def test_broadcast_success(self):
       """Test successful broadcast."""
       from unittest.mock import AsyncMock, patch, MagicMock
       from bsv.transaction import Transaction

       tx = Transaction()
       tx.hex = lambda: "deadbeef"
       tx.txid = lambda: "a" * 64

       broadcaster = WhatsOnChainBroadcaster(Network.MAINNET)

       # Mock successful response
       with patch.object(broadcaster.http_client, 'fetch') as mock_fetch:
           mock_response = MagicMock()
           mock_response.ok = True
           mock_response.status_code = 200
           mock_response.json = MagicMock(return_value={"data": "a" * 64})
           mock_fetch.return_value = mock_response

           result = await broadcaster.broadcast(tx)

           assert isinstance(result, BroadcastResponse)
           assert result.status == "success"
           assert result.txid == "a" * 64

   @pytest.mark.asyncio
   async def test_broadcast_http_error(self):
       """Test broadcast with HTTP error."""
       from unittest.mock import AsyncMock, patch, MagicMock
       from bsv.transaction import Transaction

       tx = Transaction()
       tx.hex = lambda: "deadbeef"

       broadcaster = WhatsOnChainBroadcaster(Network.MAINNET)

       # Mock error response
       with patch.object(broadcaster.http_client, 'fetch') as mock_fetch:
           mock_response = MagicMock()
           mock_response.ok = False
           mock_response.status_code = 400
           mock_response.json = MagicMock(return_value={"data": "Invalid transaction"})
           mock_fetch.return_value = mock_response

           result = await broadcaster.broadcast(tx)

           assert isinstance(result, BroadcastFailure)
           assert result.status == "error"
           assert result.code == "400"
           assert result.description == "Invalid transaction"

   @pytest.mark.asyncio
   async def test_broadcast_network_error(self):
       """Test broadcast with network error."""
       from unittest.mock import AsyncMock, patch
       from bsv.transaction import Transaction

       tx = Transaction()
       tx.hex = lambda: "deadbeef"

       broadcaster = WhatsOnChainBroadcaster(Network.MAINNET)

       # Mock network error
       with patch.object(broadcaster.http_client, 'fetch') as mock_fetch:
           mock_fetch.side_effect = Exception("Connection failed")

           result = await broadcaster.broadcast(tx)

           assert isinstance(result, BroadcastFailure)
           assert result.status == "error"
           assert result.code == "500"
           assert "Connection failed" in result.description

   def test_network_case_insensitive(self):
       """Test network string parsing is case insensitive."""
       # Test various cases
       broadcaster = WhatsOnChainBroadcaster("MAIN")
       assert broadcaster.network == 'main'

       broadcaster = WhatsOnChainBroadcaster("MainNet")
       assert broadcaster.network == 'main'

       broadcaster = WhatsOnChainBroadcaster("TEST")
       assert broadcaster.network == 'test'

       broadcaster = WhatsOnChainBroadcaster("TestNet")
       assert broadcaster.network == 'test'
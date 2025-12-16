"""
Comprehensive tests for bsv/overlay_tools/overlay_admin_token_template.py

Tests the OverlayAdminTokenTemplate class for SHIP and SLAP advertisements.
"""

import pytest
from unittest.mock import Mock, AsyncMock, patch
from bsv.overlay_tools.overlay_admin_token_template import OverlayAdminTokenTemplate
from bsv.script.script import Script


class TestOverlayAdminTokenTemplateInit:
    """Test OverlayAdminTokenTemplate initialization."""
    
    def test_init_with_wallet(self):
        """Test initialization with wallet."""
        wallet = Mock()
        template = OverlayAdminTokenTemplate(wallet)
        assert template.wallet == wallet
    
    def test_init_stores_wallet_reference(self):
        """Test that wallet reference is stored."""
        wallet = Mock()
        template = OverlayAdminTokenTemplate(wallet)
        assert template.wallet is wallet


class TestDecode:
    """Test decode static method."""
    
    def test_decode_ship_advertisement(self):
        """Test decoding a SHIP advertisement."""
        # Create mock PushDrop decode result
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop.decode') as mock_decode:
            mock_decode.return_value = {
                "fields": [
                    b"SHIP",
                    b"\x01\x02\x03",
                    b"example.com",
                    b"topic1"
                ]
            }
            
            result = OverlayAdminTokenTemplate.decode(b"script_bytes")
            
            assert result["protocol"] == "SHIP"
            assert result["identityKey"] == "010203"
            assert result["domain"] == "example.com"
            assert result["topicOrService"] == "topic1"
    
    def test_decode_slap_advertisement(self):
        """Test decoding a SLAP advertisement."""
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop.decode') as mock_decode:
            mock_decode.return_value = {
                "fields": [
                    b"SLAP",
                    b"\xAB\xCD\xEF",
                    b"service.example.com",
                    b"service1"
                ]
            }
            
            result = OverlayAdminTokenTemplate.decode(b"script_bytes")
            
            assert result["protocol"] == "SLAP"
            assert result["identityKey"] == "abcdef"
            assert result["domain"] == "service.example.com"
            assert result["topicOrService"] == "service1"
    
    def test_decode_with_string_fields(self):
        """Test decoding when fields are already strings."""
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop.decode') as mock_decode:
            mock_decode.return_value = {
                "fields": [
                    "SHIP",
                    "0123456789abcdef",
                    "test.com",
                    "topic"
                ]
            }
            
            result = OverlayAdminTokenTemplate.decode(b"script")
            
            assert result["protocol"] == "SHIP"
            assert result["identityKey"] == "0123456789abcdef"
            assert result["domain"] == "test.com"
            assert result["topicOrService"] == "topic"
    
    def test_decode_invalid_protocol(self):
        """Test decoding with invalid protocol raises error."""
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop.decode') as mock_decode:
            mock_decode.return_value = {
                "fields": [
                    b"INVALID",
                    b"\x01",
                    b"test.com",
                    b"topic"
                ]
            }
            
            with pytest.raises(ValueError, match="Invalid protocol type"):
                OverlayAdminTokenTemplate.decode(b"script")
    
    def test_decode_insufficient_fields(self):
        """Test decoding with insufficient fields raises error."""
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop.decode') as mock_decode:
            mock_decode.return_value = {
                "fields": [b"SHIP", b"\x01", b"test.com"]  # Only 3 fields
            }
            
            with pytest.raises(ValueError, match="Invalid SHIP/SLAP advertisement"):
                OverlayAdminTokenTemplate.decode(b"script")
    
    def test_decode_empty_result(self):
        """Test decoding with empty result raises error."""
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop.decode') as mock_decode:
            mock_decode.return_value = None
            
            with pytest.raises(ValueError, match="Invalid SHIP/SLAP advertisement"):
                OverlayAdminTokenTemplate.decode(b"script")
    
    def test_decode_no_fields(self):
        """Test decoding with no fields raises error."""
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop.decode') as mock_decode:
            mock_decode.return_value = {"fields": []}
            
            with pytest.raises(ValueError, match="Invalid SHIP/SLAP advertisement"):
                OverlayAdminTokenTemplate.decode(b"script")


class TestLock:
    """Test lock async method."""
    
    @pytest.mark.asyncio
    async def test_lock_ship_advertisement(self):
        """Test locking a SHIP advertisement."""
        wallet = Mock()
        wallet.get_public_key = AsyncMock(return_value=Mock(publicKey="0123456789abcdef"))
        
        template = OverlayAdminTokenTemplate(wallet)
        
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop') as MockPushDrop, \
             patch('bsv.overlay_tools.overlay_admin_token_template.Script') as MockScript:
            mock_pushdrop = Mock()
            mock_pushdrop.lock.return_value = "deadbeef"
            MockPushDrop.return_value = mock_pushdrop
            MockScript.from_hex.return_value = Mock(spec=Script)
            
            result = await template.lock("SHIP", "example.com", "topic1")
            
            wallet.get_public_key.assert_called_once()
            mock_pushdrop.lock.assert_called_once()
            MockScript.from_hex.assert_called_once_with("deadbeef")
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_lock_slap_advertisement(self):
        """Test locking a SLAP advertisement."""
        wallet = Mock()
        wallet.get_public_key = AsyncMock(return_value=Mock(publicKey="fedcba9876543210"))
        
        template = OverlayAdminTokenTemplate(wallet)
        
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop') as MockPushDrop, \
             patch('bsv.overlay_tools.overlay_admin_token_template.Script') as MockScript:
            mock_pushdrop = Mock()
            mock_pushdrop.lock.return_value = "cafebabe"
            MockPushDrop.return_value = mock_pushdrop
            MockScript.from_hex.return_value = Mock(spec=Script)
            
            result = await template.lock("SLAP", "service.com", "service1")
            
            assert result is not None
            wallet.get_public_key.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_lock_invalid_protocol(self):
        """Test locking with invalid protocol raises error."""
        wallet = Mock()
        template = OverlayAdminTokenTemplate(wallet)
        
        with pytest.raises(ValueError, match="Protocol must be either 'SHIP' or 'SLAP'"):
            await template.lock("INVALID", "example.com", "topic")
    
    @pytest.mark.asyncio
    async def test_lock_uses_correct_protocol_info_ship(self):
        """Test lock uses correct protocol info for SHIP."""
        wallet = Mock()
        wallet.get_public_key = AsyncMock(return_value=Mock(publicKey="0123"))
        
        template = OverlayAdminTokenTemplate(wallet)
        
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop') as MockPushDrop, \
             patch('bsv.overlay_tools.overlay_admin_token_template.Script') as MockScript:
            mock_pushdrop = Mock()
            mock_pushdrop.lock.return_value = "hex"
            MockPushDrop.return_value = mock_pushdrop
            MockScript.from_hex.return_value = Mock()
            
            await template.lock("SHIP", "test.com", "topic")
            
            call_args = mock_pushdrop.lock.call_args
            protocol_info = call_args[0][1]  # Second positional arg (protocol_id)
            assert protocol_info["securityLevel"] == 0
            assert "Service Host Interconnect" in protocol_info["protocol"]
    
    @pytest.mark.asyncio
    async def test_lock_uses_correct_protocol_info_slap(self):
        """Test lock uses correct protocol info for SLAP."""
        wallet = Mock()
        wallet.get_public_key = AsyncMock(return_value=Mock(publicKey="0123"))
        
        template = OverlayAdminTokenTemplate(wallet)
        
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop') as MockPushDrop, \
             patch('bsv.overlay_tools.overlay_admin_token_template.Script') as MockScript:
            mock_pushdrop = Mock()
            mock_pushdrop.lock.return_value = "hex"
            MockPushDrop.return_value = mock_pushdrop
            MockScript.from_hex.return_value = Mock()
            
            await template.lock("SLAP", "test.com", "service")
            
            call_args = mock_pushdrop.lock.call_args
            protocol_info = call_args[0][1]  # Second positional arg (protocol_id)
            assert protocol_info["securityLevel"] == 0
            assert "Service Lookup Availability" in protocol_info["protocol"]


class TestUnlock:
    """Test unlock method."""
    
    def test_unlock_ship(self):
        """Test unlocking a SHIP advertisement."""
        wallet = Mock()
        template = OverlayAdminTokenTemplate(wallet)
        
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop') as MockPushDrop:
            mock_pushdrop = Mock()
            mock_unlocker = Mock()
            mock_pushdrop.unlock.return_value = mock_unlocker
            MockPushDrop.return_value = mock_pushdrop
            
            result = template.unlock("SHIP")
            
            assert result == mock_unlocker
            mock_pushdrop.unlock.assert_called_once()
    
    def test_unlock_slap(self):
        """Test unlocking a SLAP advertisement."""
        wallet = Mock()
        template = OverlayAdminTokenTemplate(wallet)
        
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop') as MockPushDrop:
            mock_pushdrop = Mock()
            mock_unlocker = Mock()
            mock_pushdrop.unlock.return_value = mock_unlocker
            MockPushDrop.return_value = mock_pushdrop
            
            result = template.unlock("SLAP")
            
            assert result == mock_unlocker
    
    def test_unlock_invalid_protocol(self):
        """Test unlocking with invalid protocol raises error."""
        wallet = Mock()
        template = OverlayAdminTokenTemplate(wallet)
        
        with pytest.raises(ValueError, match="Protocol must be either 'SHIP' or 'SLAP'"):
            template.unlock("INVALID")
    
    def test_unlock_uses_correct_protocol_info_ship(self):
        """Test unlock uses correct protocol info for SHIP."""
        wallet = Mock()
        template = OverlayAdminTokenTemplate(wallet)
        
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop') as MockPushDrop:
            mock_pushdrop = Mock()
            MockPushDrop.return_value = mock_pushdrop
            
            template.unlock("SHIP")
            
            call_args = mock_pushdrop.unlock.call_args
            protocol_info = call_args[0][0]
            assert protocol_info["securityLevel"] == 0
            assert "Service Host Interconnect" in protocol_info["protocol"]
    
    def test_unlock_uses_correct_protocol_info_slap(self):
        """Test unlock uses correct protocol info for SLAP."""
        wallet = Mock()
        template = OverlayAdminTokenTemplate(wallet)
        
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop') as MockPushDrop:
            mock_pushdrop = Mock()
            MockPushDrop.return_value = mock_pushdrop
            
            template.unlock("SLAP")
            
            call_args = mock_pushdrop.unlock.call_args
            protocol_info = call_args[0][0]
            assert protocol_info["securityLevel"] == 0
            assert "Service Lookup Availability" in protocol_info["protocol"]


class TestEdgeCases:
    """Test edge cases and error handling."""
    
    def test_decode_with_unicode_domain(self):
        """Test decoding with unicode characters in domain."""
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop.decode') as mock_decode:
            mock_decode.return_value = {
                "fields": [
                    b"SHIP",
                    b"\x01",
                    "中文.com".encode('utf-8'),
                    b"topic"
                ]
            }
            
            result = OverlayAdminTokenTemplate.decode(b"script")
            
            assert result["domain"] == "中文.com"
    
    def test_decode_with_long_identity_key(self):
        """Test decoding with long identity key."""
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop.decode') as mock_decode:
            long_key = b"\xFF" * 64
            mock_decode.return_value = {
                "fields": [
                    b"SLAP",
                    long_key,
                    b"test.com",
                    b"service"
                ]
            }
            
            result = OverlayAdminTokenTemplate.decode(b"script")
            
            assert len(result["identityKey"]) == 128  # 64 bytes = 128 hex chars
    
    @pytest.mark.asyncio
    async def test_lock_with_empty_domain(self):
        """Test locking with empty domain string."""
        wallet = Mock()
        wallet.get_public_key = AsyncMock(return_value=Mock(publicKey="0123"))
        
        template = OverlayAdminTokenTemplate(wallet)
        
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop') as MockPushDrop, \
             patch('bsv.overlay_tools.overlay_admin_token_template.Script') as MockScript:
            mock_pushdrop = Mock()
            mock_pushdrop.lock.return_value = "hex"
            MockPushDrop.return_value = mock_pushdrop
            MockScript.from_hex.return_value = Mock()
            
            result = await template.lock("SHIP", "", "topic")
            
            assert result is not None
    
    @pytest.mark.asyncio
    async def test_lock_with_special_characters(self):
        """Test locking with special characters in fields."""
        wallet = Mock()
        wallet.get_public_key = AsyncMock(return_value=Mock(publicKey="0123"))
        
        template = OverlayAdminTokenTemplate(wallet)
        
        with patch('bsv.overlay_tools.overlay_admin_token_template.PushDrop') as MockPushDrop, \
             patch('bsv.overlay_tools.overlay_admin_token_template.Script') as MockScript:
            mock_pushdrop = Mock()
            mock_pushdrop.lock.return_value = "hex"
            MockPushDrop.return_value = mock_pushdrop
            MockScript.from_hex.return_value = Mock()
            
            result = await template.lock("SLAP", "test@#$.com", "topic!@#")
            
            assert result is not None

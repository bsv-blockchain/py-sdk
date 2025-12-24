"""
OverlayAdminTokenTemplate implementation.

Ported from TypeScript SDK.
"""

from typing import Union, TYPE_CHECKING
from bsv.script.script import Script
from bsv.transaction.pushdrop import PushDrop

if TYPE_CHECKING:
    from bsv.wallet.wallet_interface import WalletInterface


class OverlayAdminTokenTemplate:
    """
    Script template enabling the creation, unlocking, and decoding of SHIP and SLAP advertisements.

    Ported from TypeScript SDK.
    """

    def __init__(self, wallet: 'WalletInterface'):
        """
        Constructs a new Overlay Admin template instance.

        :param wallet: Wallet to use for locking and unlocking
        """
        self.wallet = wallet

    @staticmethod
    def decode(script: Union[Script, bytes]) -> dict:
        """
        Decodes a SHIP or SLAP advertisement from a given locking script.

        :param script: Locking script comprising a SHIP or SLAP token to decode
        :returns: Decoded SHIP or SLAP advertisement
        """
        # Convert to bytes if needed
        if isinstance(script, Script):
            script_bytes = bytes.fromhex(script.to_hex())
        else:
            script_bytes = script

        # Decode using PushDrop
        result = PushDrop.decode(script_bytes)

        if not result or len(result.get("fields", [])) < 4:
            raise ValueError("Invalid SHIP/SLAP advertisement!")

        fields = result["fields"]

        # Extract protocol
        protocol_bytes = fields[0]
        if isinstance(protocol_bytes, str):
            protocol = protocol_bytes
        else:
            protocol = protocol_bytes.decode('utf-8')

        if protocol not in ['SHIP', 'SLAP']:
            raise ValueError("Invalid protocol type!")

        # Extract identity key
        identity_key_bytes = fields[1]
        if isinstance(identity_key_bytes, bytes):
            identity_key = identity_key_bytes.hex()
        else:
            identity_key = identity_key_bytes

        # Extract domain
        domain_bytes = fields[2]
        if isinstance(domain_bytes, str):
            domain = domain_bytes
        else:
            domain = domain_bytes.decode('utf-8')

        # Extract topic or service
        topic_or_service_bytes = fields[3]
        if isinstance(topic_or_service_bytes, str):
            topic_or_service = topic_or_service_bytes
        else:
            topic_or_service = topic_or_service_bytes.decode('utf-8')

        return {
            "protocol": protocol,
            "identityKey": identity_key,
            "domain": domain,
            "topicOrService": topic_or_service
        }

    async def lock(self, protocol: str, domain: str, topic_or_service: str) -> Script:
        """
        Creates a new advertisement locking script.

        :param protocol: SHIP or SLAP
        :param domain: Domain where the topic or service is available
        :param topic_or_service: Topic or service to advertise
        :returns: Locking script comprising the advertisement token
        """
        if protocol not in ['SHIP', 'SLAP']:
            raise ValueError("Protocol must be either 'SHIP' or 'SLAP'")

        # Get identity key from wallet
        identity_key_result = await self.wallet.get_public_key({
            "identityKey": True
        })
        identity_key = identity_key_result.publicKey

        # Create PushDrop fields
        fields = [
            protocol.encode('utf-8'),
            bytes.fromhex(identity_key),
            domain.encode('utf-8'),
            topic_or_service.encode('utf-8')
        ]

        # Create PushDrop script
        pushdrop = PushDrop(self.wallet, None)

        # Get appropriate protocol info based on protocol type
        if protocol == 'SHIP':
            protocol_info = {
                "securityLevel": 0,
                "protocol": "Service Host Interconnect"
            }
        else:  # SLAP
            protocol_info = {
                "securityLevel": 0,
                "protocol": "Service Lookup Availability"
            }

        # Create locking script using PushDrop
        locking_script_hex = pushdrop.lock(
            fields,
            protocol_info,
            "1",  # key_id
            "self",  # counterparty
            include_signature=False  # For advertisements, we don't need signatures
        )

        return Script.from_hex(locking_script_hex)

    def unlock(self, protocol: str):
        """
        Unlocks an advertisement token as part of a transaction.

        :param protocol: SHIP or SLAP, depending on the token to unlock
        :returns: Script unlocker capable of unlocking the advertisement token
        """
        if protocol not in ['SHIP', 'SLAP']:
            raise ValueError("Protocol must be either 'SHIP' or 'SLAP'")

        # Create PushDrop unlocker
        pushdrop = PushDrop(self.wallet, None)

        # Get appropriate protocol info based on protocol type
        if protocol == 'SHIP':
            protocol_info = {
                "securityLevel": 0,
                "protocol": "Service Host Interconnect"
            }
        else:  # SLAP
            protocol_info = {
                "securityLevel": 0,
                "protocol": "Service Lookup Availability"
            }

        # Get unlocker
        unlocker = pushdrop.unlock(
            protocol_info,
            "1",  # key_id
            "self"  # counterparty
        )

        return unlocker

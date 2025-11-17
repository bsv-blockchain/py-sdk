"""
ContactsManager implementation for managing on-chain contacts.

This module provides functionality to store, retrieve, update, and delete
contacts stored on the blockchain using PushDrop scripts.
"""
from typing import Optional, List, Dict, Any
import json
from bsv.wallet.wallet_interface import WalletInterface
from bsv.identity.types import DisplayableIdentity
from bsv.transaction.pushdrop import PushDrop
from bsv.hash import hmac_sha256
from bsv.utils import unsigned_to_varint


CONTACT_PROTOCOL_ID = [2, 'contact']
CONTACTS_CACHE_KEY = 'metanet-contacts'


class Contact(DisplayableIdentity):
    """Contact type extending DisplayableIdentity with optional metadata."""
    metadata: Optional[Dict[str, Any]] = None


class ContactsManager:
    """
    Manages contacts stored on-chain using PushDrop scripts.
    
    Contacts are stored encrypted in blockchain outputs with tags for
    efficient lookup by identity key.
    """

    def __init__(self, wallet: Optional[WalletInterface] = None):
        """
        Initialize ContactsManager.
        
        Args:
            wallet: Wallet interface for blockchain operations
        """
        if wallet is None:
            from bsv.wallet.wallet_impl import WalletImpl
            from bsv.keys import PrivateKey
            wallet = WalletImpl(PrivateKey())
        self.wallet = wallet
        self._cache: Dict[str, str] = {}

    def get_contacts(
        self,
        identity_key: Optional[str] = None,
        force_refresh: bool = False,
        limit: int = 1000
    ) -> List[Contact]:
        """
        Load all records from the contacts basket.
        
        Args:
            identity_key: Optional specific identity key to fetch
            force_refresh: Whether to force a check for new contact data
            limit: Maximum number of contacts to return
            
        Returns:
            List of Contact objects
        """
        # Check cache first unless forcing refresh
        if not force_refresh:
            cached = self._cache.get(CONTACTS_CACHE_KEY)
            if cached:
                try:
                    cached_contacts = json.loads(cached)
                    if identity_key:
                        return [c for c in cached_contacts if c.get('identityKey') == identity_key]
                    return cached_contacts
                except Exception:
                    pass

        # Build tags for filtering
        tags = []
        if identity_key:
            # Hash the identity key to use as a tag
            hashed_key = hmac_sha256(
                bytes(json.dumps(CONTACT_PROTOCOL_ID), 'utf-8'),
                identity_key.encode('utf-8')
            )
            tags.append(f'identityKey {hashed_key.hex()}')

        # Get contact outputs from the contacts basket
        outputs_result = self.wallet.list_outputs(None, {
            'basket': 'contacts',
            'include': 'locking scripts',
            'includeCustomInstructions': True,
            'tags': tags,
            'limit': limit
        }, None) or {}

        outputs = outputs_result.get('outputs') or []
        beef = outputs_result.get('BEEF') or b''

        if not outputs:
            self._cache[CONTACTS_CACHE_KEY] = json.dumps([])
            return []

        contacts = []
        pushdrop = PushDrop(self.wallet, None)

        # Process each contact output
        for output in outputs:
            try:
                locking_script_hex = output.get('lockingScript') or ''
                if not locking_script_hex:
                    continue

                # Decode PushDrop script
                decoded = pushdrop.decode(bytes.fromhex(locking_script_hex))
                if not decoded or not decoded.get('fields'):
                    continue

                # Get keyID from custom instructions
                custom_instructions = output.get('customInstructions')
                if not custom_instructions:
                    continue

                key_id_data = json.loads(custom_instructions)
                key_id = key_id_data.get('keyID')

                # Decrypt contact data
                ciphertext = decoded['fields'][0]
                decrypt_result = self.wallet.decrypt(None, {
                    'ciphertext': ciphertext,
                    'protocolID': CONTACT_PROTOCOL_ID,
                    'keyID': key_id,
                    'counterparty': 'self'
                }, None) or {}

                plaintext = decrypt_result.get('plaintext') or b''
                contact_data = json.loads(plaintext.decode('utf-8'))
                contacts.append(contact_data)
            except Exception:
                # Skip malformed contacts
                continue

        # Cache results
        self._cache[CONTACTS_CACHE_KEY] = json.dumps(contacts)
        return contacts

    def save_contact(
        self,
        contact: DisplayableIdentity,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Save or update a Metanet contact.
        
        Args:
            contact: The displayable identity information for the contact
            metadata: Optional metadata to store with the contact
        """
        # Get current contacts
        contacts = self.get_contacts()
        
        # Check if contact already exists
        existing_index = next(
            (i for i, c in enumerate(contacts) if c.get('identityKey') == contact.get('identityKey')),
            None
        )

        contact_to_store = {**contact, 'metadata': metadata}

        # Hash identity key for tagging
        identity_key = contact.get('identityKey', '')
        hashed_key = hmac_sha256(
            bytes(json.dumps(CONTACT_PROTOCOL_ID), 'utf-8'),
            identity_key.encode('utf-8')
        )

        # Generate keyID
        import secrets
        key_id = secrets.token_bytes(32).hex()

        # Check for existing output
        existing_output = None
        outputs_result = self.wallet.list_outputs(None, {
            'basket': 'contacts',
            'include': 'entire transactions',
            'includeCustomInstructions': True,
            'tags': [f'identityKey {hashed_key.hex()}'],
            'limit': 100
        }, None) or {}

        existing_outputs = outputs_result.get('outputs') or []
        beef = outputs_result.get('BEEF') or b''

        # Try to find existing output by decrypting and checking identityKey
        for output in existing_outputs:
            try:
                custom_instructions = output.get('customInstructions')
                if custom_instructions:
                    key_id_data = json.loads(custom_instructions)
                    key_id = key_id_data.get('keyID', key_id)

                # Decrypt and check if this is the right contact
                # (simplified - full implementation would decode from BEEF)
                if output.get('outpoint'):
                    existing_output = output
                    break
            except Exception:
                continue

        # Encrypt contact data
        contact_json = json.dumps(contact_to_store)
        encrypt_result = self.wallet.encrypt(None, {
            'plaintext': contact_json.encode('utf-8'),
            'protocolID': CONTACT_PROTOCOL_ID,
            'keyID': key_id,
            'counterparty': 'self'
        }, None) or {}

        ciphertext = encrypt_result.get('ciphertext') or b''

        # Create locking script
        pushdrop = PushDrop(self.wallet, None)
        locking_script = pushdrop.lock(
            None,
            [ciphertext],
            CONTACT_PROTOCOL_ID,
            key_id,
            {'type': 0},  # self
            for_self=True,
            include_signature=True,
            lock_position='before'
        )

        if existing_output:
            # Update existing contact
            outpoint = existing_output.get('outpoint', '').split('.')
            if len(outpoint) == 2:
                txid, vout = outpoint
                create_result = self.wallet.create_action(None, {
                    'description': 'Update Contact',
                    'inputBEEF': beef,
                    'inputs': [{
                        'outpoint': {'txid': txid, 'index': int(vout)},
                        'unlockingScriptLength': 74,
                        'inputDescription': 'Spend previous contact output'
                    }],
                    'outputs': [{
                        'basket': 'contacts',
                        'satoshis': 1,
                        'lockingScript': locking_script,
                        'outputDescription': f'Updated Contact: {contact.get("name", identity_key[:10])}',
                        'tags': [f'identityKey {hashed_key.hex()}'],
                        'customInstructions': json.dumps({'keyID': key_id})
                    }]
                }, None)
        else:
            # Create new contact
            self.wallet.create_action(None, {
                'description': 'Add Contact',
                'outputs': [{
                    'basket': 'contacts',
                    'satoshis': 1,
                    'lockingScript': locking_script,
                    'outputDescription': f'Contact: {contact.get("name", identity_key[:10])}',
                    'tags': [f'identityKey {hashed_key.hex()}'],
                    'customInstructions': json.dumps({'keyID': key_id})
                }]
            }, None)

        # Clear cache
        self._cache.pop(CONTACTS_CACHE_KEY, None)

    def delete_contact(self, identity_key: str) -> None:
        """
        Delete a contact by spending its output.
        
        Args:
            identity_key: The identity key of the contact to delete
        """
        # Find the contact output
        contacts = self.get_contacts(identity_key=identity_key, force_refresh=True)
        if not contacts:
            return

        # Get outputs for this identity key
        hashed_key = hmac_sha256(
            bytes(json.dumps(CONTACT_PROTOCOL_ID), 'utf-8'),
            identity_key.encode('utf-8')
        )

        outputs_result = self.wallet.list_outputs(None, {
            'basket': 'contacts',
            'include': 'entire transactions',
            'tags': [f'identityKey {hashed_key.hex()}'],
            'limit': 100
        }, None) or {}

        outputs = outputs_result.get('outputs') or []
        beef = outputs_result.get('BEEF') or b''

        if not outputs:
            return

        # Spend the contact output (create transaction with no outputs)
        for output in outputs:
            outpoint = output.get('outpoint', '').split('.')
            if len(outpoint) == 2:
                txid, vout = outpoint
                self.wallet.create_action(None, {
                    'description': 'Delete Contact',
                    'inputBEEF': beef,
                    'inputs': [{
                        'outpoint': {'txid': txid, 'index': int(vout)},
                        'unlockingScriptLength': 74,
                        'inputDescription': 'Spend contact output'
                    }],
                    'outputs': []
                }, None)
                break

        # Clear cache
        self._cache.pop(CONTACTS_CACHE_KEY, None)


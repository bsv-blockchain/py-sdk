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
            cached_contacts = self._get_cached_contacts(identity_key)
            if cached_contacts is not None:
                return cached_contacts

        # Fetch and process contact outputs
        tags = self._build_contact_tags(identity_key)
        outputs = self._fetch_contact_outputs(tags, limit)

        if not outputs:
            self._cache[CONTACTS_CACHE_KEY] = json.dumps([])
            return []

        contacts = self._process_contact_outputs(outputs)
        
        # Cache results
        self._cache[CONTACTS_CACHE_KEY] = json.dumps(contacts)
        return contacts

    def _get_cached_contacts(self, identity_key: Optional[str]) -> Optional[List[Contact]]:
        """Get contacts from cache if available."""
        cached = self._cache.get(CONTACTS_CACHE_KEY)
        if cached:
            try:
                cached_contacts = json.loads(cached)
                if identity_key:
                    return [c for c in cached_contacts if c.get('identityKey') == identity_key]
                return cached_contacts
            except Exception:
                pass
        return None

    def _build_contact_tags(self, identity_key: Optional[str]) -> List[str]:
        """Build tags for filtering contacts."""
        tags = []
        if identity_key:
            hashed_key = self._hash_identity_key(identity_key)
            tags.append(f'identityKey {hashed_key.hex()}')
        return tags

    def _fetch_contact_outputs(self, tags: List[str], limit: int) -> List[Dict]:
        """Fetch contact outputs from wallet."""
        outputs_result = self.wallet.list_outputs(None, {
            'basket': 'contacts',
            'include': 'locking scripts',
            'includeCustomInstructions': True,
            'tags': tags,
            'limit': limit
        }, None) or {}
        return outputs_result.get('outputs') or []

    def _process_contact_outputs(self, outputs: List[Dict]) -> List[Contact]:
        """Process contact outputs and decrypt contact data."""
        contacts = []
        pushdrop = PushDrop(self.wallet, None)

        for output in outputs:
            try:
                contact_data = self._decrypt_contact_output(output, pushdrop)
                if contact_data:
                    contacts.append(contact_data)
            except Exception:
                continue
        
        return contacts

    def _decrypt_contact_output(self, output: Dict, pushdrop: PushDrop) -> Optional[Dict]:
        """Decrypt a single contact output."""
        locking_script_hex = output.get('lockingScript') or ''
        if not locking_script_hex:
            return None

        decoded = pushdrop.decode(bytes.fromhex(locking_script_hex))
        if not decoded or not decoded.get('fields'):
            return None

        custom_instructions = output.get('customInstructions')
        if not custom_instructions:
            return None

        key_id_data = json.loads(custom_instructions)
        key_id = key_id_data.get('keyID')

        ciphertext = decoded['fields'][0]
        decrypt_result = self.wallet.decrypt(None, {
            'ciphertext': ciphertext,
            'protocolID': CONTACT_PROTOCOL_ID,
            'keyID': key_id,
            'counterparty': 'self'
        }, None) or {}

        plaintext = decrypt_result.get('plaintext') or b''
        return json.loads(plaintext.decode('utf-8'))

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
        contact_to_store = {**contact, 'metadata': metadata}
        identity_key = contact.get('identityKey', '')
        hashed_key = self._hash_identity_key(identity_key)
        
        # Generate keyID and find existing output
        import secrets
        key_id = secrets.token_bytes(32).hex()
        existing_output, beef, key_id = self._find_existing_contact_output(hashed_key, key_id)
        
        # Encrypt and create locking script
        locking_script = self._create_contact_locking_script(contact_to_store, key_id)
        
        # Create or update contact
        self._save_or_update_contact_action(
            existing_output, beef, locking_script, 
            contact, identity_key, hashed_key, key_id
        )
        
        # Clear cache
        self._cache.pop(CONTACTS_CACHE_KEY, None)

    def _hash_identity_key(self, identity_key: str) -> bytes:
        """Hash identity key for tagging."""
        return hmac_sha256(
            bytes(json.dumps(CONTACT_PROTOCOL_ID), 'utf-8'),
            identity_key.encode('utf-8')
        )

    def _find_existing_contact_output(self, hashed_key: bytes, key_id: str) -> tuple:
        """Find existing contact output if any."""
        outputs_result = self.wallet.list_outputs(None, {
            'basket': 'contacts',
            'include': 'entire transactions',
            'includeCustomInstructions': True,
            'tags': [f'identityKey {hashed_key.hex()}'],
            'limit': 100
        }, None) or {}

        existing_outputs = outputs_result.get('outputs') or []
        beef = outputs_result.get('BEEF') or b''

        for output in existing_outputs:
            try:
                custom_instructions = output.get('customInstructions')
                if custom_instructions:
                    key_id_data = json.loads(custom_instructions)
                    key_id = key_id_data.get('keyID', key_id)

                if output.get('outpoint'):
                    return output, beef, key_id
            except Exception:
                continue
        
        return None, beef, key_id

    def _create_contact_locking_script(self, contact_to_store: Dict, key_id: str) -> str:
        """Create encrypted locking script for contact."""
        contact_json = json.dumps(contact_to_store)
        encrypt_result = self.wallet.encrypt(None, {
            'plaintext': contact_json.encode('utf-8'),
            'protocolID': CONTACT_PROTOCOL_ID,
            'keyID': key_id,
            'counterparty': 'self'
        }, None) or {}

        ciphertext = encrypt_result.get('ciphertext') or b''
        pushdrop = PushDrop(self.wallet, None)
        return pushdrop.lock(
            None, [ciphertext], CONTACT_PROTOCOL_ID, key_id,
            {'type': 0}, for_self=True, include_signature=True, lock_position='before'
        )

    def _save_or_update_contact_action(
        self, existing_output, beef, locking_script, 
        contact, identity_key, hashed_key, key_id
    ) -> None:
        """Create wallet action to save or update contact."""
        if existing_output:
            outpoint = existing_output.get('outpoint', '').split('.')
            if len(outpoint) == 2:
                txid, vout = outpoint
                self.wallet.create_action(None, {
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


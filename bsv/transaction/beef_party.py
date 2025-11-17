"""
BeefParty implementation for multi-party BEEF exchange.

Translated from ts-sdk/src/transaction/BeefParty.ts
"""
from typing import Dict, List, Optional, Union
from bsv.transaction.beef import Beef, BEEF_V2


class BeefParty(Beef):
    """
    Extends Beef for exchanging transaction validity data with multiple parties.
    
    Tracks which parties know which transactions to reduce re-transmission.
    """

    def __init__(self, parties: Optional[List[str]] = None):
        """
        Initialize BeefParty.
        
        Args:
            parties: Optional list of initial party identifiers
        """
        super().__init__(BEEF_V2)
        self.known_to: Dict[str, Dict[str, bool]] = {}
        if parties:
            for party in parties:
                self.add_party(party)

    def is_party(self, party: str) -> bool:
        """
        Check if party exists.
        
        Args:
            party: Party identifier
            
        Returns:
            True if party exists
        """
        return party in self.known_to

    def add_party(self, party: str) -> None:
        """
        Add a new unique party identifier.
        
        Args:
            party: Party identifier
            
        Raises:
            ValueError: If party already exists
        """
        if self.is_party(party):
            raise ValueError(f'Party {party} already exists.')
        self.known_to[party] = {}

    def get_known_txids_for_party(self, party: str) -> List[str]:
        """
        Get array of txids known to party.
        
        Args:
            party: Party identifier
            
        Returns:
            List of known txids
            
        Raises:
            ValueError: If party is unknown
        """
        known_txids = self.known_to.get(party)
        if known_txids is None:
            raise ValueError(f'Party {party} is unknown.')
        return list(known_txids.keys())

    def get_trimmed_beef_for_party(self, party: str) -> Beef:
        """
        Get trimmed beef of unknown transactions and proofs for party.
        
        Args:
            party: Party identifier
            
        Returns:
            Trimmed Beef instance
        """
        known_txids = self.get_known_txids_for_party(party)
        pruned_beef = self.clone()
        pruned_beef.trim_known_txids(known_txids)
        return pruned_beef

    def add_known_txids_for_party(self, party: str, known_txids: List[str]) -> None:
        """
        Mark additional txids as known to party.
        
        Args:
            party: Party identifier (added if new)
            known_txids: List of txids known to party
        """
        if not self.is_party(party):
            self.add_party(party)
        kts = self.known_to[party]
        for txid in known_txids:
            kts[txid] = True
            self.merge_txid_only(txid)

    def merge_beef_from_party(self, party: str, beef: Union[bytes, Beef]) -> None:
        """
        Merge beef received from a specific party.
        
        Updates this BeefParty to track all txids corresponding to transactions
        for which party has raw transaction and validity proof data.
        
        Args:
            party: Party identifier
            beef: Beef to merge (bytes or Beef instance)
        """
        if isinstance(beef, bytes):
            b = Beef.from_binary(beef)
        else:
            b = beef
        known_txids = b.get_valid_txids()
        self.merge_beef(b)
        self.add_known_txids_for_party(party, known_txids)


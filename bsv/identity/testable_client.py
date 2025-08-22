from typing import Optional, List, Dict, Any
from .client import IdentityClient
from .types import DisplayableIdentity, IdentityClientOptions, CertificateFieldNameUnder50Bytes, OriginatorDomainNameStringUnder250Bytes

class TestableIdentityClient(IdentityClient):
    """
    Testable version of IdentityClient. Allows injection of wallet and originator, records call history, and returns dummy values for easy testing.
    """
    def __init__(self, wallet: Optional[Any] = None, options: Optional[IdentityClientOptions] = None, originator: OriginatorDomainNameStringUnder250Bytes = "", record_calls: bool = True):
        super().__init__(wallet, options, originator)
        self.record_calls = record_calls
        self.calls: List[Dict[str, Any]] = []
        self._dummy_txid = "dummy-txid"
        self._dummy_identities = [DisplayableIdentity(name="Test User", identity_key="testkey1")]  # Dummy identity for tests

    def _record(self, method: str, **kwargs):
        if self.record_calls:
            self.calls.append({"method": method, **kwargs})

    def publicly_reveal_attributes(self, ctx: Any, certificate: Any, fields_to_reveal: List[CertificateFieldNameUnder50Bytes]):
        """
        Simulate revealing some certificate attributes. Returns a dummy txid and the fields.
        """
        self._record("publicly_reveal_attributes", ctx=ctx, certificate=certificate, fields_to_reveal=fields_to_reveal)
        return {"txid": self._dummy_txid, "fields": fields_to_reveal}

    def publicly_reveal_attributes_simple(self, ctx: Any, certificate: Any, fields_to_reveal: List[CertificateFieldNameUnder50Bytes]) -> str:
        """
        Simulate simple attribute reveal. Returns only a dummy txid.
        """
        self._record("publicly_reveal_attributes_simple", ctx=ctx, certificate=certificate, fields_to_reveal=fields_to_reveal)
        return self._dummy_txid

    def resolve_by_identity_key(self, ctx: Any, args: Dict) -> List[DisplayableIdentity]:
        """
        Simulate resolving identities by identity key. Returns a dummy identity list.
        """
        self._record("resolve_by_identity_key", ctx=ctx, args=args)
        return self._dummy_identities

    def resolve_by_attributes(self, ctx: Any, args: Dict) -> List[DisplayableIdentity]:
        """
        Simulate resolving identities by attributes. Returns a dummy identity list.
        """
        self._record("resolve_by_attributes", ctx=ctx, args=args)
        return self._dummy_identities

    @staticmethod
    def parse_identity(identity: Any) -> DisplayableIdentity:
        """
        For tests: If identity is DisplayableIdentity, return as is. If dict, extract name and identity_key.
        """
        if isinstance(identity, DisplayableIdentity):
            return identity
        if isinstance(identity, dict):
            return DisplayableIdentity(
                name=identity.get("name", "Test Identity"),
                identity_key=identity.get("identity_key", "testkey1")
            )
        return DisplayableIdentity(name="Unknown Test Identity")

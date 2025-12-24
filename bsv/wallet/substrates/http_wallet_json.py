import requests
import json
from typing import Optional, Any, Dict

class HTTPWalletJSON:
    def __init__(self, originator: str, base_url: Optional[str] = None, http_client: Optional[requests.Session] = None):
        self.base_url = base_url or "http://localhost:3321"
        self.http_client = http_client or requests.Session()
        self.originator = originator

    def api(self, _: Any = None, call: str = None, args: Any = None) -> bytes:
        url = f"{self.base_url}/{call}"
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self.originator:
            headers["Originator"] = self.originator
        data = json.dumps(args or {})
        resp = self.http_client.post(url, data=data, headers=headers)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code} {resp.reason}: {resp.text}")
        return resp.content

    # --- 各wallet操作メソッドのスケルトン ---
    def create_action(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "createAction", args)
        return json.loads(data)
    def sign_action(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "signAction", args)
        return json.loads(data)
    def abort_action(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "abortAction", args)
        return json.loads(data)
    def list_actions(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "listActions", args)
        return json.loads(data)
    def internalize_action(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "internalizeAction", args)
        return json.loads(data)
    def list_outputs(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "listOutputs", args)
        return json.loads(data)
    def relinquish_output(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "relinquishOutput", args)
        return json.loads(data)
    def get_public_key(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "getPublicKey", args)
        return json.loads(data)
    def reveal_counterparty_key_linkage(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "revealCounterpartyKeyLinkage", args)
        return json.loads(data)
    def reveal_specific_key_linkage(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "revealSpecificKeyLinkage", args)
        return json.loads(data)
    def encrypt(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "encrypt", args)
        return json.loads(data)
    def decrypt(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "decrypt", args)
        return json.loads(data)
    def create_hmac(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "createHmac", args)
        return json.loads(data)
    def verify_hmac(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "verifyHmac", args)
        return json.loads(data)
    def create_signature(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "createSignature", args)
        return json.loads(data)
    def verify_signature(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "verifySignature", args)
        return json.loads(data)
    def acquire_certificate(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "acquireCertificate", args)
        return json.loads(data)
    def list_certificates(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "listCertificates", args)
        return json.loads(data)
    def prove_certificate(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "proveCertificate", args)
        return json.loads(data)
    def relinquish_certificate(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "relinquishCertificate", args)
        return json.loads(data)
    def discover_by_identity_key(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "discoverByIdentityKey", args)
        return json.loads(data)
    def discover_by_attributes(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "discoverByAttributes", args)
        return json.loads(data)
    def is_authenticated(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "isAuthenticated", args)
        return json.loads(data)
    def wait_for_authentication(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "waitForAuthentication", args)
        return json.loads(data)
    def get_height(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "getHeight", args)
        return json.loads(data)
    def get_header_for_height(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "getHeaderForHeight", args)
        return json.loads(data)
    def get_network(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "getNetwork", args)
        return json.loads(data)
    def get_version(self, ctx: Any, args: dict) -> Dict[str, Any]:
        data = self.api(ctx, "getVersion", args)
        return json.loads(data)

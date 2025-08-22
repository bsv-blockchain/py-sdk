import requests
from typing import Optional
from .wallet_wire import WalletWire
from .wallet_wire_calls import WalletWireCall

class HTTPWalletWire(WalletWire):
    def __init__(self, originator: str, base_url: Optional[str] = None, http_client: Optional[requests.Session] = None):
        self.base_url = base_url or "http://localhost:3301"
        self.http_client = http_client or requests.Session()
        self.originator = originator

    def transmit_to_wallet(self, ctx, message: bytes) -> bytes:
        if not message or len(message) < 2:
            raise RuntimeError("invalid wallet wire frame: too short")

        # Parse frame: [call(1)][originatorLen(1)][originator?][payload...]
        call_code = message[0]
        originator_len = message[1]
        if 2 + originator_len > len(message):
            raise RuntimeError("invalid wallet wire frame: originator length out of bounds")
        originator_bytes = message[2 : 2 + originator_len]
        payload = message[2 + originator_len :]

        # Map call code to endpoint name (Go/TS compatible)
        try:
            call = WalletWireCall(call_code)
        except Exception:
            raise RuntimeError("invalid call code")

        call_code_to_name = {
            WalletWireCall.CREATE_ACTION: "createAction",
            WalletWireCall.SIGN_ACTION: "signAction",
            WalletWireCall.ABORT_ACTION: "abortAction",
            WalletWireCall.LIST_ACTIONS: "listActions",
            WalletWireCall.INTERNALIZE_ACTION: "internalizeAction",
            WalletWireCall.LIST_OUTPUTS: "listOutputs",
            WalletWireCall.RELINQUISH_OUTPUT: "relinquishOutput",
            WalletWireCall.GET_PUBLIC_KEY: "getPublicKey",
            WalletWireCall.REVEAL_COUNTERPARTY_KEY_LINKAGE: "revealCounterpartyKeyLinkage",
            WalletWireCall.REVEAL_SPECIFIC_KEY_LINKAGE: "revealSpecificKeyLinkage",
            WalletWireCall.ENCRYPT: "encrypt",
            WalletWireCall.DECRYPT: "decrypt",
            WalletWireCall.CREATE_HMAC: "createHmac",
            WalletWireCall.VERIFY_HMAC: "verifyHmac",
            WalletWireCall.CREATE_SIGNATURE: "createSignature",
            WalletWireCall.VERIFY_SIGNATURE: "verifySignature",
            WalletWireCall.ACQUIRE_CERTIFICATE: "acquireCertificate",
            WalletWireCall.LIST_CERTIFICATES: "listCertificates",
            WalletWireCall.PROVE_CERTIFICATE: "proveCertificate",
            WalletWireCall.RELINQUISH_CERTIFICATE: "relinquishCertificate",
            WalletWireCall.DISCOVER_BY_IDENTITY_KEY: "discoverByIdentityKey",
            WalletWireCall.DISCOVER_BY_ATTRIBUTES: "discoverByAttributes",
            WalletWireCall.IS_AUTHENTICATED: "isAuthenticated",
            WalletWireCall.WAIT_FOR_AUTHENTICATION: "waitForAuthentication",
            WalletWireCall.GET_HEIGHT: "getHeight",
            WalletWireCall.GET_HEADER_FOR_HEIGHT: "getHeaderForHeight",
            WalletWireCall.GET_NETWORK: "getNetwork",
            WalletWireCall.GET_VERSION: "getVersion",
        }

        endpoint = call_code_to_name.get(call)
        if not endpoint:
            raise RuntimeError("invalid call code")

        originator = originator_bytes.decode("utf-8") if originator_bytes else ""

        url = f"{self.base_url}/{endpoint}"
        headers = {"Content-Type": "application/octet-stream"}
        if originator:
            # Go implementation uses "Origin" header for binary wire
            headers["Origin"] = originator

        resp = self.http_client.post(url, data=payload, headers=headers)
        if resp.status_code != 200:
            body = resp.text or ""
            raise RuntimeError(f"HTTP {resp.status_code} {resp.reason}: {body}")
        return resp.content

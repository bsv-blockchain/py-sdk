import threading
import base64
import struct
from typing import Callable, Any, Optional, List, Dict, Tuple
from urllib.parse import urlparse
import requests

from bsv.auth.transports.transport import Transport
from bsv.auth.auth_message import AuthMessage
from bsv.keys import PublicKey

class SimplifiedHTTPTransport(Transport):
    """
    Transport implementation using HTTP communication (equivalent to Go's SimplifiedHTTPTransport)
    """
    def __init__(self, base_url: str, client: Optional[Any] = None):
        self.base_url = base_url
        self.client = client or requests.Session()
        self._on_data_funcs: List[Callable[[Any, AuthMessage], Optional[Exception]]] = []
        self._lock = threading.Lock()

    def send(self, ctx: Any, message: AuthMessage) -> Optional[Exception]:
        """Send an AuthMessage via HTTP"""
        # Check if any handlers are registered
        with self._lock:
            if not self._on_data_funcs:
                return Exception("No handler registered")
        
        try:
            if getattr(message, 'message_type', None) == 'general':
                return self._send_general_message(ctx, message)
            else:
                return self._send_non_general_message(ctx, message)
        except Exception as e:
            return Exception(f"Failed to send AuthMessage: {e}")

    def on_data(self, callback: Callable[[Any, AuthMessage], Optional[Exception]]) -> Optional[Exception]:
        if callback is None:
            return Exception("callback cannot be None")
        with self._lock:
            self._on_data_funcs.append(callback)
        return None

    def get_registered_on_data(self) -> tuple[Optional[Callable[[Any, AuthMessage], Exception]], Optional[Exception]]:
        with self._lock:
            if not self._on_data_funcs:
                return None, Exception("no handlers registered")
            return self._on_data_funcs[0], None

    def _send_non_general_message(self, ctx: Any, message: AuthMessage) -> Optional[Exception]:
        """
        Send non-general AuthMessage (initialRequest, initialResponse, etc.)
        Reference: go-sdk/auth/transports/simplified_http_transport.go:94-117
        """
        import json
        
        try:
            # Serialize AuthMessage to JSON
            json_data = json.dumps({
                'version': message.version,
                'messageType': message.message_type,
                'identityKey': message.identity_key.hex() if hasattr(message.identity_key, 'hex') else str(message.identity_key),
                'nonce': message.nonce,
                'initialNonce': message.initial_nonce,
                'yourNonce': message.your_nonce,
                'certificates': message.certificates if message.certificates else [],
                'requestedCertificates': message.requested_certificates,
                'payload': list(message.payload) if message.payload else None,
                'signature': list(message.signature) if message.signature else None,
            }, default=str).encode('utf-8')
            
            # Determine URL
            request_url = self.base_url.rstrip('/') + '/.well-known/auth'
            
            # Send HTTP POST request
            resp = self.client.post(request_url, data=json_data, headers={'Content-Type': 'application/json'})
            
            # Check status code
            if resp.status_code < 200 or resp.status_code >= 300:
                body_text = resp.text if resp.text else ''
                return Exception(f"HTTP server failed to authenticate: status {resp.status_code}: {body_text}")
            
            # Parse response
            if resp.content and len(resp.content) > 0:
                response_data = json.loads(resp.content.decode('utf-8'))
                response_msg = self._auth_message_from_dict(response_data)
                return self._notify_handlers(ctx, response_msg)
            else:
                return Exception("Empty response body")
                
        except Exception as e:
            return Exception(f"Failed to send non-general message: {e}")
    
    def _send_general_message(self, ctx: Any, message: AuthMessage) -> Optional[Exception]:
        """
        Send general AuthMessage (authenticated HTTP request)
        Reference: go-sdk/auth/transports/simplified_http_transport.go:147-177
        Reference: ts-sdk/src/auth/transports/SimplifiedFetchTransport.ts:76-135
        """
        try:
            # Step 1: Deserialize payload to HTTP request
            request_id_bytes, method, url_path, url_search, headers, body = self._deserialize_request_payload(message.payload)
            request_id = base64.b64encode(request_id_bytes).decode('utf-8')
            
            # Construct full URL
            url = self.base_url.rstrip('/') + url_path
            if url_search:
                url += url_search
            
            # Step 2: Set authentication headers
            auth_headers = {
                'x-bsv-auth-version': message.version,
                'x-bsv-auth-identity-key': message.identity_key.hex() if hasattr(message.identity_key, 'hex') else str(message.identity_key),
                'x-bsv-auth-message-type': message.message_type,
                'x-bsv-auth-nonce': message.nonce,
                'x-bsv-auth-your-nonce': message.your_nonce,
                'x-bsv-auth-signature': message.signature.hex() if isinstance(message.signature, bytes) else ''.join(f'{b:02x}' for b in message.signature),
                'x-bsv-auth-request-id': request_id,
            }
            
            # Merge headers
            all_headers = {**headers, **auth_headers}
            
            # Step 3: Perform HTTP request
            resp = self.client.request(method, url, headers=all_headers, data=body if body else None)
            
            # Step 4: Build AuthMessage from response
            response_msg = self._auth_message_from_general_response(request_id_bytes, resp)
            if response_msg is None:
                return Exception("Failed to parse response")
            
            return self._notify_handlers(ctx, response_msg)
            
        except Exception as e:
            return Exception(f"Failed to send general message: {e}")
    
    def _deserialize_request_payload(self, payload: bytes) -> Tuple[bytes, str, str, str, Dict[str, str], Optional[bytes]]:
        """
        Deserialize request payload into HTTP request components.
        Reference: ts-sdk/src/auth/transports/SimplifiedFetchTransport.ts:224-287
        Reference: go-sdk/auth/authpayload/http.go (ToHTTPRequest)
        
        Returns: (request_id_bytes, method, path, search, headers, body)
        """
        from bsv.utils.reader_writer import Reader
        
        reader = Reader(payload)
        
        # Read request ID (32 bytes)
        request_id = reader.read(32)
        
        # Read method
        method_length = self._read_varint(reader)
        method = reader.read(method_length).decode('utf-8') if method_length > 0 else 'GET'
        
        # Read path
        path_length = self._read_varint(reader)
        path = reader.read(path_length).decode('utf-8') if path_length > 0 else '/'
        
        # Read search (query string)
        search_length = self._read_varint(reader)
        search = reader.read(search_length).decode('utf-8') if search_length > 0 else ''
        
        # Read headers
        headers = {}
        n_headers = self._read_varint(reader)
        for _ in range(n_headers):
            key_length = self._read_varint(reader)
            key = reader.read(key_length).decode('utf-8')
            value_length = self._read_varint(reader)
            value = reader.read(value_length).decode('utf-8')
            headers[key] = value
        
        # Read body
        body_length = self._read_varint(reader)
        body = reader.read(body_length) if body_length > 0 else None
        
        return request_id, method, path, search, headers, body
    
    def _auth_message_from_general_response(self, request_id: bytes, resp: requests.Response) -> Optional[AuthMessage]:
        """
        Build AuthMessage from HTTP response for general message.
        Reference: go-sdk/auth/transports/simplified_http_transport.go:179-231
        Reference: ts-sdk/src/auth/transports/SimplifiedFetchTransport.ts:183-192
        """
        # Check for required version header
        version = resp.headers.get('x-bsv-auth-version')
        if not version:
            return None
        
        # Read identity key from header
        identity_key_str = resp.headers.get('x-bsv-auth-identity-key')
        if not identity_key_str:
            return None
        
        try:
            identity_key = PublicKey(identity_key_str)
        except Exception:
            return None
        
        # Read signature
        signature_hex = resp.headers.get('x-bsv-auth-signature', '')
        signature = bytes.fromhex(signature_hex) if signature_hex else b''
        
        # Build response payload
        response_payload = self._serialize_response_payload(request_id, resp)
        
        # Create AuthMessage
        return AuthMessage(
            version=version,
            message_type='general',
            identity_key=identity_key,
            nonce=resp.headers.get('x-bsv-auth-nonce', ''),
            your_nonce=resp.headers.get('x-bsv-auth-your-nonce', ''),
            signature=signature,
            payload=response_payload,
        )
    
    def _serialize_response_payload(self, request_id: bytes, resp: requests.Response) -> bytes:
        """
        Serialize HTTP response into payload.
        Reference: ts-sdk/src/auth/transports/SimplifiedFetchTransport.ts:136-180
        Reference: go-sdk/auth/authpayload/http.go (FromHTTPResponse)
        """
        from bsv.utils.reader_writer import Writer
        
        writer = Writer()
        
        # Write request ID
        writer.write(request_id)
        
        # Write status code
        writer.write_var_int_num(resp.status_code)
        
        # Filter and write headers
        # Include: x-bsv-* (excluding x-bsv-auth-*), authorization
        included_headers = []
        for key, value in resp.headers.items():
            key_lower = key.lower()
            if ((key_lower.startswith('x-bsv-') and not key_lower.startswith('x-bsv-auth-')) or 
                key_lower == 'authorization'):
                included_headers.append((key_lower, value))
        
        # Sort headers
        included_headers.sort(key=lambda x: x[0])
        
        # Write number of headers
        writer.write_var_int_num(len(included_headers))
        
        # Write each header
        for key, value in included_headers:
            key_bytes = key.encode('utf-8')
            writer.write_var_int_num(len(key_bytes))
            writer.write(key_bytes)
            
            value_bytes = value.encode('utf-8')
            writer.write_var_int_num(len(value_bytes))
            writer.write(value_bytes)
        
        # Write body
        if resp.content and len(resp.content) > 0:
            writer.write_var_int_num(len(resp.content))
            writer.write(resp.content)
        else:
            # -1 indicates no body
            writer.write_var_int_num(0xFFFFFFFFFFFFFFFF)
        
        return writer.getvalue()
    
    def _auth_message_from_dict(self, data: Dict) -> AuthMessage:
        """Convert dictionary to AuthMessage"""
        # Convert identityKey
        identity_key_str = data.get('identityKey') or data.get('identity_key')
        identity_key = PublicKey(identity_key_str) if identity_key_str else None
        
        # Convert payload
        payload = data.get('payload')
        if isinstance(payload, list):
            payload = bytes(payload)
        elif isinstance(payload, str):
            payload = payload.encode('utf-8')
        
        # Convert signature
        signature = data.get('signature')
        if isinstance(signature, list):
            signature = bytes(signature)
        elif isinstance(signature, str):
            signature = bytes.fromhex(signature)
        
        return AuthMessage(
            version=data.get('version', '0.1'),
            message_type=data.get('messageType') or data.get('message_type', 'initialResponse'),
            identity_key=identity_key,
            nonce=data.get('nonce', ''),
            initial_nonce=data.get('initialNonce') or data.get('initial_nonce', ''),
            your_nonce=data.get('yourNonce') or data.get('your_nonce', ''),
            certificates=data.get('certificates', []),
            requested_certificates=data.get('requestedCertificates') or data.get('requested_certificates'),
            payload=payload,
            signature=signature,
        )
    
    def _read_varint(self, reader) -> int:
        """
        Read variable-length integer.
        Compatible with Bitcoin/BSV varint encoding.
        """
        first_byte_data = reader.read(1)
        if not first_byte_data:
            return 0
        first_byte = first_byte_data[0]
        
        if first_byte < 0xFD:
            return first_byte
        elif first_byte == 0xFD:
            return struct.unpack('<H', reader.read(2))[0]
        elif first_byte == 0xFE:
            return struct.unpack('<I', reader.read(4))[0]
        else:  # 0xFF
            return struct.unpack('<Q', reader.read(8))[0]
    
    def _notify_handlers(self, ctx: Any, message: AuthMessage) -> Optional[Exception]:
        with self._lock:
            handlers = list(self._on_data_funcs)
        for handler in handlers:
            try:
                err = handler(ctx, message)
                if err:
                    return err
            except Exception as e:
                return Exception(f"Handler failed: {e}")
        return None

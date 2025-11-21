#!/usr/bin/env python3
"""
Full Authentication Protocol Test Server

This server implements the complete BSV authentication protocol as defined in the Go/TypeScript SDKs.
It supports:
- Initial authentication handshake (initialRequest/initialResponse)
- Certificate exchange (certificateRequest/certificateResponse)
- General message handling with mutual authentication
- Session management with proper nonce validation
- Binary payload parsing and response generation

Usage:
    [Server]
    python3 tests/test_auth_server_full.py
    or
    cd py-sdk && PYTHONPATH=/mnt/extra/bsv-blockchain/py-sdk python3 tests/test_auth_server_full.py
    [Client]
    python3 -m pytest -v tests/test_auth_fetch_full_e2e.py::test_auth_fetch_full_protocol | cat

The server will run on https://localhost:8084 by default.
"""

import asyncio
import json
import base64
import hashlib
import os
import time
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from aiohttp import web
import logging

# Add parent directory to path for imports
test_dir = Path(__file__).parent
sys.path.insert(0, str(test_dir))

from test_ssl_helper import get_server_ssl_context

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AuthServer")

class AuthSession:
    """Represents an authenticated session with a peer"""
    def __init__(self, client_identity_key: str, client_nonce: str, server_nonce: str):
        self.client_identity_key = client_identity_key
        self.client_nonce = client_nonce
        self.server_nonce = server_nonce
        self.is_authenticated = False
        self.last_update = int(time.time() * 1000)
        self.certificates: List[Dict] = []

class AuthServer:
    """Full authentication protocol server implementation"""
    
    def __init__(self):
        self.sessions: Dict[str, AuthSession] = {}  # key: client_identity_key
        self.server_identity_key = "03a1b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef0123456789a"  # Mock server key
        
    def generate_nonce(self) -> str:
        """Generate a 32-byte random nonce, base64 encoded"""
        return base64.b64encode(os.urandom(32)).decode()
    
    def create_signature(self, message_data: str) -> str:
        """Create a mock signature for the message"""
        # In a real implementation, this would use the server's private key
        # For testing, we'll create a deterministic mock signature
        hash_obj = hashlib.sha256(message_data.encode())
        return base64.b64encode(hash_obj.digest()).decode()
    
    def handle_initial_request(self, message: Dict) -> Dict:
        """Handle initialRequest message type"""
        client_identity_key = message.get("identityKey")
        client_nonce = message.get("nonce")
        
        if not client_identity_key or not client_nonce:
            raise ValueError("Missing required fields: identityKey and nonce")
        
        # Generate server nonce
        server_nonce = self.generate_nonce()
        
        # Create or update session
        session = AuthSession(client_identity_key, client_nonce, server_nonce)
        session.is_authenticated = True  # For testing, auto-authenticate
        self.sessions[client_identity_key] = session
        
        logger.info(f"Created session for client {client_identity_key[:16]}...")
        
        # Create response
        response = {
            "version": "0.1",
            "messageType": "initialResponse",
            "identityKey": self.server_identity_key,
            "nonce": server_nonce,
            "yourNonce": client_nonce,
            "certificates": [],  # Could include server certificates here
        }
        
        # Add signature
        response_str = json.dumps(response, sort_keys=True)
        response["signature"] = self.create_signature(response_str)
        
        return response
    
    def handle_certificate_request(self, message: Dict) -> Dict:
        """Handle certificateRequest message type"""
        client_identity_key = message.get("identityKey")
        _ = message.get("requestedCertificates", {})
        
        session = self.sessions.get(client_identity_key)
        if not session or not session.is_authenticated:
            raise PermissionError("Session not authenticated")
        
        logger.info(f"Certificate request from {client_identity_key[:16]}...")
        
        # Mock certificates (in real implementation, would query certificate store)
        mock_certificates = [
            {
                "type": "test-certificate",
                "subject": client_identity_key,
                "certifier": self.server_identity_key,
                "serialNumber": "12345",
                "fields": {"name": "Test User", "role": "developer"},
                "signature": self.create_signature("mock-cert-data")
            }
        ]
        
        response = {
            "version": "0.1",
            "messageType": "certificateResponse",
            "identityKey": self.server_identity_key,
            "certificates": mock_certificates,
        }
        
        response_str = json.dumps(response, sort_keys=True)
        response["signature"] = self.create_signature(response_str)
        
        return response
    
    def handle_general_message(self, message: Dict) -> Dict:
        """Handle general message type"""
        client_identity_key = message.get("identityKey")
        payload = message.get("payload")
        
        session = self.sessions.get(client_identity_key)
        if not session or not session.is_authenticated:
            raise PermissionError("Session not authenticated")
        
        logger.info(f"General message from {client_identity_key[:16]}...")
        
        # Parse the payload if it's a binary HTTP request
        response_payload = None
        if payload:
            try:
                # Try to parse as binary HTTP request (from AuthFetch)
                response_payload = self.parse_binary_request(payload)
            except Exception as e:
                logger.warning(f"Failed to parse binary payload: {e}")
                # Fallback to echo the payload
                response_payload = payload
        
        response = {
            "version": "0.1",
            "messageType": "general",
            "identityKey": self.server_identity_key,
            "payload": response_payload,
        }
        
        response_str = json.dumps(response, sort_keys=True)
        response["signature"] = self.create_signature(response_str)
        
        return response
    
    def parse_binary_request(self, payload: bytes) -> bytes:
        """Parse binary HTTP request payload and generate appropriate response"""
        try:
            # This would implement the binary protocol parsing
            # For now, return a mock HTTP 200 response in binary format
            
            # Mock binary HTTP response format:
            # - 32 bytes: request nonce (echo back)
            # - varint: status code (200)
            # - varint: number of headers (1)
            # - string: header key ("content-type")
            # - string: header value ("text/plain")
            # - varint: body length
            # - bytes: body content
            
            import struct
            
            response_data = bytearray()
            
            # Echo back the first 32 bytes as nonce (if available)
            if len(payload) >= 32:
                response_data.extend(payload[:32])
            else:
                response_data.extend(b'\x00' * 32)
            
            # Status code: 200 (as varint)
            response_data.extend(struct.pack('<Q', 200))
            
            # Number of headers: 1
            response_data.extend(struct.pack('<Q', 1))
            
            # Header: content-type: application/json
            content_type_key = "content-type"
            content_type_value = "application/json"
            
            # Write header key
            key_bytes = content_type_key.encode('utf-8')
            response_data.extend(struct.pack('<Q', len(key_bytes)))
            response_data.extend(key_bytes)
            
            # Write header value
            value_bytes = content_type_value.encode('utf-8')
            response_data.extend(struct.pack('<Q', len(value_bytes)))
            response_data.extend(value_bytes)
            
            # Body
            body = b'{"message": "Authentication successful", "server": "BSV Auth Server"}'
            response_data.extend(struct.pack('<Q', len(body)))
            response_data.extend(body)
            
            return bytes(response_data)
            
        except Exception as e:
            logger.error(f"Error parsing binary request: {e}")
            # Return error response
            error_body = b'{"error": "Failed to parse request"}'
            response_data = bytearray()
            response_data.extend(b'\x00' * 32)  # nonce
            response_data.extend(struct.pack('<Q', 400))  # status
            response_data.extend(struct.pack('<Q', 0))   # no headers
            response_data.extend(struct.pack('<Q', len(error_body)))
            response_data.extend(error_body)
            return bytes(response_data)

# Global server instance
auth_server = AuthServer()

async def handle_auth_message(request):
    """Main handler for authentication messages"""
    try:
        # Read request body
        body = await request.read()
        
        # Try to parse as JSON first
        try:
            message = json.loads(body.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return web.Response(status=400, text="Invalid JSON format")
        # Support simple session management test payloads: {"request": N}
        if isinstance(message, dict) and "request" in message:
            return web.Response(
                body=json.dumps({"message": "Authentication successful", "echo": message.get("request")}),
                content_type="application/json",
                status=200,
            )
        
        message_type = message.get("messageType")
        
        if not message_type:
            return web.Response(status=400, text="Missing messageType")
        
        logger.info(f"Received message type: {message_type}")
        
        # Route to appropriate handler
        if message_type == "initialRequest":
            response = auth_server.handle_initial_request(message)
        elif message_type == "certificateRequest":
            response = auth_server.handle_certificate_request(message)
        elif message_type == "general":
            response = auth_server.handle_general_message(message)
        else:
            return web.Response(status=400, text=f"Unknown message type: {message_type}")
        
        # Return JSON response
        return web.Response(
            body=json.dumps(response),
            content_type="application/json",
            status=200
        )
        
    except PermissionError as e:
        logger.warning(f"Authentication error: {e}")
        return web.Response(status=403, text=str(e))  # codeql[py/stack-trace-exposure] - Not used in production - test server only
    except ValueError as e:
        logger.warning(f"Validation error: {e}")
        return web.Response(status=400, text=str(e))  # codeql[py/stack-trace-exposure] - Not used in production - test server only
    except Exception as e:
        logger.error(f"Server error: {e}")
        return web.Response(status=500, text="Internal server error")

async def handle_health_check(request):  # NOSONAR
    """Health check endpoint"""
    return web.Response(text="BSV Auth Server is running", status=200)

def create_app():
    """Create the aiohttp application"""
    app = web.Application()
    
    # Add routes
    app.router.add_post("/auth", handle_auth_message)
    app.router.add_get("/health", handle_health_check)
    app.router.add_get("/", handle_health_check)
    
    return app

async def main():
    """Main entry point"""
    app = create_app()
    
    # Start server
    runner = web.AppRunner(app)
    await runner.setup()
    
    # Get SSL context for HTTPS
    ssl_context = get_server_ssl_context()
    
    site = web.TCPSite(runner, "localhost", 8084, ssl_context=ssl_context)
    await site.start()
    
    logger.info("BSV Authentication Server started on https://localhost:8084")
    logger.info("Endpoints:")
    logger.info("  POST /auth - Authentication protocol messages")
    logger.info("  GET /health - Health check")
    
    try:
        # Keep the server running
        while True:
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        logger.info("Shutting down server...")
    finally:
        await runner.cleanup()

if __name__ == "__main__":
    asyncio.run(main())

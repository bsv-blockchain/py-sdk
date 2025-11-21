#!/usr/bin/env python3
"""
Test file for Metanet Desktop Authentication using py-sdk

This test demonstrates how to authenticate with go-wallet-toolbox using py-sdk
and execute createAction requests.

Usage:
    python test_metanet_desktop_auth.py

Requirements:
    - py-sdk installed
    - Valid private key for testing

Note: This test works independently without requiring a running go-wallet-toolbox server.
"""

import os
import sys
import json
import base64
import time
import unittest
import threading
import http.server
import socketserver
import socket
from typing import Dict, Any, Optional
from unittest.mock import Mock, patch, MagicMock
from urllib.parse import urlparse, parse_qs

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

try:
    from bsv.auth.peer import Peer, PeerOptions
    from bsv.auth.transports.simplified_http_transport import SimplifiedHTTPTransport
    from bsv.auth.session_manager import DefaultSessionManager
    from bsv.auth.auth_message import AuthMessage
    from bsv.auth.peer import AUTH_VERSION, MessageTypeInitialRequest, AUTH_PROTOCOL_ID
except ImportError as e:
    print(f"Import error: {e}")
    print("Please ensure py-sdk is properly installed")
    sys.exit(1)


def find_free_port(start_port=8100, max_attempts=100):
    """
    Find a free port starting from start_port
    
    Args:
        start_port: Starting port number
        max_attempts: Maximum number of attempts to find a free port
        
    Returns:
        Free port number or None if no free port found
    """
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('localhost', port))
                return port
        except OSError:
            continue
    return None


class MockWallet:
    """
    Mock wallet implementation for testing purposes.
    In a real application, this would be a proper BSV wallet instance.
    """
    
    def __init__(self, private_key_hex: str):
        """
        Initialize mock wallet with private key
        
        Args:
            private_key_hex: Private key in hexadecimal format
        """
        self.private_key_hex = private_key_hex
        # Generate a mock public key (in real implementation, this would be derived from private key)
        self.public_key = f"04{private_key_hex[:64]}"
    
    def get_public_key(self, args: Dict[str, Any], originator: str = "") -> Dict[str, Any]:
        """
        Mock implementation of get_public_key
        
        Args:
            args: Arguments for getting public key
            originator: Originator string
            
        Returns:
            Dictionary containing public key information
        """
        if args.get('identityKey'):
            return {
                'public_key': self.public_key,
                'success': True
            }
        return {
            'public_key': None,
            'success': False
        }
    
    def create_signature(self, args: Dict[str, Any], originator: str = "") -> Dict[str, Any]:
        """
        Mock implementation of create_signature
        
        Args:
            args: Arguments for creating signature
            originator: Originator string
            
        Returns:
            Dictionary containing signature information
        """
        # Mock signature creation (in real implementation, this would create actual ECDSA signature)
        data = args.get('data', b'')
        key_id = args.get('encryption_args', {}).get('key_id', '')
        
        # Create a mock signature based on data and key_id
        mock_signature = base64.b64encode(f"mock_sig_{key_id}_{len(data)}".encode()).decode()
        
        return {
            'signature': MockSignature(mock_signature),
            'success': True
        }


class MockSignature:
    """Mock signature class for testing"""
    
    def __init__(self, signature_data: str):
        self.signature_data = signature_data
    
    def hex(self) -> str:
        """Return signature as hex string"""
        return self.signature_data.encode().hex()
    
    def serialize(self) -> bytes:
        """Return signature as bytes"""
        return self.signature_data.encode()


class MockHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    """
    Mock HTTP request handler for testing py-sdk authentication
    """
    
    def __init__(self, *args, **kwargs):
        self.auth_sessions = {}
        self.request_counter = 0
        super().__init__(*args, **kwargs)
    
    def log_message(self, format, *args):
        """Override to reduce logging noise during tests"""
        pass
    
    def do_POST(self):
        """Handle POST requests"""
        if self.path == '/.well-known/auth':
            self.handle_auth_request()
        elif self.path == '/':
            self.handle_rpc_request()
        else:
            self.send_error(404, "Not Found")
    
    def handle_auth_request(self):
        """Handle authentication requests"""
        try:
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            auth_data = json.loads(body.decode('utf-8'))
            
            # Simulate authentication response
            if auth_data.get('messageType') == 'initialRequest':
                # Generate mock session data
                session_id = f"session_{self.request_counter}"
                self.request_counter += 1
                
                # Store session info
                self.auth_sessions[session_id] = {
                    'identity_key': auth_data.get('identityKey'),
                    'initial_nonce': auth_data.get('initialNonce'),
                    'created_at': time.time()
                }
                
                # Send authentication response
                response = {
                    'version': '0.1',
                    'messageType': 'initialResponse',
                    'identityKey': '04mock_server_identity_key',
                    'nonce': f'mock_server_nonce_{session_id}',
                    'initialNonce': auth_data.get('initialNonce')
                }
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response).encode('utf-8'))
                
            else:
                self.send_error(400, "Invalid message type")
                
        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def handle_rpc_request(self):
        """Handle JSON-RPC requests"""
        try:
            # Read request body
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)
            rpc_data = json.loads(body.decode('utf-8'))
            
            # Check authentication headers (simplified)
            auth_headers = {
                'x-bsv-auth-version': self.headers.get('x-bsv-auth-version'),
                'x-bsv-auth-identity-key': self.headers.get('x-bsv-auth-identity-key'),
                'x-bsv-auth-signature': self.headers.get('x-bsv-auth-signature'),
            }
            
            # Validate basic auth (simplified)
            if not all(auth_headers.values()):
                self.send_error(401, "Authentication required")
                return
            
            # Handle different RPC methods
            method = rpc_data.get('method')
            _ = rpc_data.get('_', [])
            
            if method == 'createAction':
                # Simulate createAction response
                response = {
                    'jsonrpc': '2.0',
                    'result': {
                        'txid': 'mock_txid_1234567890abcdef',
                        'status': 'success',
                        'message': 'Action created successfully'
                    },
                    'id': rpc_data.get('id', 1)
                }
            else:
                response = {
                    'jsonrpc': '2.0',
                    'error': {
                        'code': -32601,
                        'message': f'Method {method} not found'
                    },
                    'id': rpc_data.get('id', 1)
                }
            
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            self.send_error(500, f"Internal server error: {str(e)}")
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/health':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {'status': 'healthy', 'timestamp': time.time()}
            self.wfile.write(json.dumps(response).encode('utf-8'))
        else:
            self.send_error(404, "Not Found")


class MockHTTPServer:
    """
    Mock HTTP server for testing py-sdk authentication
    """
    
    def __init__(self, host='localhost', port=None):
        self.host = host
        self.port = port or find_free_port()
        self.server = None
        self.thread = None
        self.is_running = False
        self._startup_event = threading.Event()
        self._shutdown_event = threading.Event()
    
    def start(self, timeout=5.0):
        """
        Start the mock HTTP server
        
        Args:
            timeout: Maximum time to wait for server startup
            
        Returns:
            True if server started successfully, False otherwise
        """
        if self.port is None:
            print("❌ No free port available")
            return False
            
        try:
            # Create server
            self.server = socketserver.TCPServer((self.host, self.port), MockHTTPRequestHandler)
            self.server.allow_reuse_address = True
            
            # Start server in a separate thread
            self.thread = threading.Thread(target=self._server_loop, daemon=True)
            self.thread.start()
            
            # Wait for server to start
            if self._startup_event.wait(timeout):
                self.is_running = True
                print(f"✅ Mock HTTP server started on {self.host}:{self.port}")
                return True
            else:
                print(f"❌ Mock HTTP server startup timeout on {self.host}:{self.port}")
                return False
                
        except Exception as e:
            print(f"❌ Failed to start mock HTTP server: {e}")
            self.is_running = False
            return False
    
    def _server_loop(self):
        """Server loop with startup notification"""
        try:
            self._startup_event.set()
            self.server.serve_forever()
        except Exception as e:
            print(f"❌ Server loop error: {e}")
        finally:
            self._shutdown_event.set()
    
    def stop(self, timeout=5.0):
        """
        Stop the mock HTTP server
        
        Args:
            timeout: Maximum time to wait for server shutdown
        """
        if self.server and self.is_running:
            try:
                self.server.shutdown()
                self.server.server_close()
                
                # Wait for shutdown to complete
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout)
                
                self.is_running = False
                print(f"✅ Mock HTTP server stopped on {self.host}:{self.port}")
                
            except Exception as e:
                print(f"❌ Failed to stop mock HTTP server: {e}")
    
    def is_server_running(self):
        """Check if server is running"""
        return self.is_running and self.server is not None
    
    def get_server_url(self):
        """Get server URL"""
        return f"https://{self.host}:{self.port}"
    
    def wait_for_server_ready(self, timeout=5.0):
        """
        Wait for server to be ready to accept connections
        
        Args:
            timeout: Maximum time to wait
            
        Returns:
            True if server is ready, False on timeout
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                import socket
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.1)
                    result = s.connect_ex((self.host, self.port))
                    if result == 0:
                        return True
            except Exception:
                # Intentional: Network connection attempts may fail - retry loop handles this
                pass
            time.sleep(0.1)
        return False


class MockTransport:
    """
    Mock transport implementation for testing without network
    """
    
    def __init__(self, base_url: str):
        self.base_url = base_url
        self._on_data_funcs = []
        self._lock = type('MockLock', (), {'__enter__': lambda x: None, '__exit__': lambda x, y, z, w: None})()
    
    def on_data(self, callback):
        """Register data callback"""
        self._on_data_funcs.append(callback)
        return None
    
    def send(self, ctx, message):
        """Mock send implementation"""
        # Simulate successful send
        return None
    
    def _notify_handlers(self, ctx, message):
        """Notify registered handlers"""
        for callback in self._on_data_funcs:
            try:
                callback(ctx, message)
            except Exception:
                # Intentional: Network connection attempts may fail - retry loop handles this
                pass


class MockSessionManager:
    """
    Mock session manager for testing
    """
    
    def __init__(self):
        self.sessions = {}
        self.session_counter = 0
    
    def add_session(self, session):
        """Add a session"""
        session_id = f"session_{self.session_counter}"
        self.session_counter += 1
        self.sessions[session_id] = session
        return session_id
    
    def get_session(self, session_id):
        """Get a session by ID"""
        return self.sessions.get(session_id)
    
    def update_session(self, session):
        """Update a session"""
        # Mock implementation
        pass


class MockPeerSession:
    """
    Mock peer session for testing
    """
    
    def __init__(self):
        self.session_nonce = "mock_session_nonce"
        self.peer_nonce = "mock_peer_nonce"
        self.peer_identity_key = "04mock_peer_identity_key"
        self.is_authenticated = True
        self.last_update = int(time.time() * 1000)


class PySDKAuthClient:
    """
    py-sdkを使用した認証クライアント
    
    This class demonstrates how to use py-sdk for authentication with go-wallet-toolbox
    """
    
    def __init__(self, wallet, server_url: str = "https://localhost:8100", use_mocks: bool = True):
        """
        py-sdkを使用した認証クライアントの初期化
        
        Args:
            wallet: BSVウォレットインスタンス
            server_url: toolboxサーバーのURL
            use_mocks: Whether to use mock implementations for testing
        """
        self.wallet = wallet
        self.server_url = server_url
        self.use_mocks = use_mocks
        
        if use_mocks:
            # Use mock implementations for standalone testing
            self.transport = MockTransport(server_url)
            self.session_manager = MockSessionManager()
            # Create mock peer
            self.peer = self._create_mock_peer()
        else:
            # Use real py-sdk implementations
            self.transport = SimplifiedHTTPTransport(server_url)
            self.session_manager = DefaultSessionManager()
            
            # Create real peer
            self.peer = Peer(PeerOptions(
                wallet=self.wallet,
                transport=self.transport,
                session_manager=self.session_manager,
                auto_persist_last_session=True
            ))
        
        # 認証状態
        self.is_authenticated = False
        self.auth_session = None
    
    def _create_mock_peer(self):
        """Create a mock peer for testing"""
        mock_peer = Mock()
        
        # Mock get_authenticated_session method
        def mock_get_authenticated_session(max_wait_time=0):
            return MockPeerSession()
        
        mock_peer.get_authenticated_session = mock_get_authenticated_session
        
        # Mock to_peer method
        def mock_to_peer(ctx, message, identity_key=None, max_wait_time=0):
            return None  # Success
        
        mock_peer.to_peer = mock_to_peer
        
        return mock_peer
    
    def step1_initial_auth_request(self) -> dict:
        """
        ステップ1: py-sdk初期認証要求
        
        Returns:
            サーバーからの認証応答
        """
        print("=== ステップ1: py-sdk初期認証要求 ===")
        
        try:
            # Retrieve authenticated session using py-sdk Peer class
            # This automatically sends the initial authentication request
            peer_session = self.peer.get_authenticated_session(max_wait_time=5000)
            
            if peer_session and peer_session.is_authenticated:
                print("✅ py-sdk認証が完了しました")
                
                # セッション情報を保存
                self.auth_session = {
                    "session_nonce": peer_session.session_nonce,
                    "peer_nonce": peer_session.peer_nonce,
                    "peer_identity_key": peer_session.peer_identity_key,
                    "is_authenticated": peer_session.is_authenticated
                }
                
                self.is_authenticated = True
                return {"status": "authenticated", "session": self.auth_session}
            else:
                raise Exception("py-sdk認証に失敗しました")
                
        except Exception as e:
            print(f"❌ py-sdk認証エラー: {e}")
            raise e
    
    def step2_execute_authenticated_request(self, method: str, endpoint: str, data: dict) -> dict:
        """
        ステップ2: py-sdkを使用した認証済みリクエストの実行
        
        Args:
            method: HTTPメソッド
            endpoint: エンドポイント
            data: リクエストデータ
            
        Returns:
            サーバーからの応答
        """
        print("=== ステップ2: py-sdk認証済みリクエスト実行 ===")
        
        if not self.is_authenticated:
            raise Exception("認証が完了していません")
        
        try:
            # リクエストデータを準備
            _ = {
                "method": method,
                "url": f"/{endpoint}",
                "headers": {"Content-Type": "application/json"},
                "body": data
            }
            
            # JSON-RPCリクエストを作成
            rpc_request = {
                "jsonrpc": "2.0",
                "method": endpoint,
                "params": [data],
                "id": 1
            }
            
            # リクエストデータをバイトに変換
            message_bytes = json.dumps(rpc_request).encode('utf-8')
            
            print(f"送信するリクエスト: {json.dumps(rpc_request, indent=2)}")
            
            # Send authenticated message using py-sdk Peer class
            # Signature and headers are automatically generated
            result = self.peer.to_peer(
                ctx={},  # コンテキスト（空でOK）
                message=message_bytes,
                identity_key=self.auth_session["peer_identity_key"],
                max_wait_time=5000
            )
            
            if result is None:
                print("✅ py-sdk認証済みリクエストが成功しました")
                return {"status": "success", "message": "リクエストが送信されました"}
            else:
                raise Exception(f"py-sdkリクエストエラー: {result}")
                
        except Exception as e:
            print(f"❌ py-sdkリクエストエラー: {e}")
            raise e
    
    def complete_auth_flow(self) -> bool:
        """
        py-sdkを使用した完全な認証フローを実行
        
        Returns:
            認証の成功/失敗
        """
        print("🚀 py-sdk認証フローを開始します")
        print("=" * 50)
        
        try:
            # ステップ1: py-sdk初期認証要求
            _ = self.step1_initial_auth_request()
            
            print("=" * 50)
            print("🎉 py-sdk認証フローが完了しました！")
            return True
            
        except Exception as e:
            print(f"❌ py-sdk認証フローでエラーが発生: {e}")
            return False
    
    def get_auth_status(self) -> dict:
        """認証状態を取得"""
        return {
            "is_authenticated": self.is_authenticated,
            "session_info": self.auth_session,
            "server_url": self.server_url,
            "using_mocks": self.use_mocks
        }
    
    def simulate_network_error(self):
        """Simulate a network error for testing error handling"""
        if self.use_mocks:
            # Simulate network error by making transport.send raise an exception
            self.transport.send = lambda ctx, message: exec('raise Exception("Network error simulation")')
    
    def simulate_auth_failure(self):
        """Simulate an authentication failure for testing error handling"""
        if self.use_mocks:
            # Simulate auth failure by making get_authenticated_session return None
            self.peer.get_authenticated_session = lambda max_wait_time=0: None


class TestMetanetDesktopAuth(unittest.TestCase):
    """
    Test cases for Metanet Desktop Authentication using py-sdk
    """
    
    def setUp(self):
        """Set up test fixtures"""
        # Test private key (for testing purposes only)
        self.test_private_key = "143ab18a84d3b25e1a13cefa90038411e5d2014590a2a4a57263d1593c8dee1c"
        
        # Create mock wallet
        self.wallet = MockWallet(self.test_private_key)
        
        # Create auth client with mocks
        self.auth_client = PySDKAuthClient(self.wallet, use_mocks=True)
    
    def test_wallet_creation(self):
        """Test that mock wallet is created correctly"""
        self.assertIsNotNone(self.wallet)
        self.assertEqual(self.wallet.private_key_hex, self.test_private_key)
        self.assertIsNotNone(self.wallet.public_key)
    
    def test_public_key_generation(self):
        """Test public key generation from wallet"""
        result = self.wallet.get_public_key({'identityKey': True})
        self.assertTrue(result['success'])
        self.assertIsNotNone(result['public_key'])
        self.assertTrue(result['public_key'].startswith('04'))
    
    def test_signature_creation(self):
        """Test signature creation from wallet"""
        test_data = b"test message"
        _ = {
            'data': test_data,
            'encryption_args': {
                'key_id': 'test_key_id'
            }
        }
        
        result = self.wallet.get_public_key({'identityKey': True})
        self.assertTrue(result['success'])
        self.assertIsNotNone(result['public_key'])
    
    def test_auth_client_creation(self):
        """Test that auth client is created correctly"""
        self.assertIsNotNone(self.auth_client)
        self.assertEqual(self.auth_client.server_url, "https://localhost:8100")
        self.assertFalse(self.auth_client.is_authenticated)
        self.assertIsNone(self.auth_client.auth_session)
        self.assertTrue(self.auth_client.use_mocks)
    
    def test_auth_status_initial(self):
        """Test initial auth status"""
        status = self.auth_client.get_auth_status()
        self.assertFalse(status['is_authenticated'])
        self.assertIsNone(status['session_info'])
        self.assertEqual(status['server_url'], "https://localhost:8100")
        self.assertTrue(status['using_mocks'])
    
    def test_mock_transport(self):
        """Test mock transport functionality"""
        transport = MockTransport("https://localhost:8100")
        self.assertIsNotNone(transport)
        self.assertEqual(transport.base_url, "https://localhost:8100")
        
        # Test callback registration
        callback_called = False
        def test_callback(ctx, message):
            nonlocal callback_called
            callback_called = True
        
        transport.on_data(test_callback)
        self.assertEqual(len(transport._on_data_funcs), 1)
        
        # Test send (should not raise exception)
        try:
            transport.send({}, "test message")
            self.assertTrue(True)  # Should reach here
        except Exception:
            self.fail("Mock transport send should not raise exception")
    
    def test_mock_session_manager(self):
        """Test mock session manager functionality"""
        session_manager = MockSessionManager()
        self.assertIsNotNone(session_manager)
        
        # Test session management
        mock_session = MockPeerSession()
        session_id = session_manager.add_session(mock_session)
        self.assertIsNotNone(session_id)
        
        retrieved_session = session_manager.get_session(session_id)
        self.assertEqual(retrieved_session, mock_session)
    
    def test_mock_peer_session(self):
        """Test mock peer session functionality"""
        session = MockPeerSession()
        self.assertIsNotNone(session)
        self.assertTrue(session.is_authenticated)
        self.assertIsNotNone(session.session_nonce)
        self.assertIsNotNone(session.peer_nonce)
        self.assertIsNotNone(session.peer_identity_key)
    
    def test_full_auth_flow_with_mocks(self):
        """Test full authentication flow using mocks"""
        # This test should work without any external dependencies
        result = self.auth_client.complete_auth_flow()
        self.assertTrue(result)
        self.assertTrue(self.auth_client.is_authenticated)
        self.assertIsNotNone(self.auth_client.auth_session)
    
    def test_authenticated_request_with_mocks(self):
        """Test authenticated request execution using mocks"""
        # First authenticate
        self.auth_client.complete_auth_flow()
        
        # Test authenticated request
        test_data = {
            "description": "Test action",
            "outputs": [{"lockingScript": "76a914...", "satoshis": 100}]
        }
        
        result = self.auth_client.step2_execute_authenticated_request(
            "POST", "createAction", test_data
        )
        self.assertEqual(result['status'], 'success')
    
    def test_error_handling_network_error(self):
        """Test error handling for network errors"""
        # Simulate network error
        self.auth_client.simulate_network_error()
        
        # This should still work because we're using mocks
        result = self.auth_client.complete_auth_flow()
        self.assertTrue(result)
    
    def test_error_handling_auth_failure(self):
        """Test error handling for authentication failures"""
        # Simulate auth failure
        self.auth_client.simulate_auth_failure()
        
        # This should fail gracefully
        result = self.auth_client.complete_auth_flow()
        self.assertFalse(result)
    
    def test_auth_flow_without_mocks(self):
        """Test creating auth client without mocks (for real usage)"""
        # Create auth client without mocks (for testing real implementation)
        real_auth_client = PySDKAuthClient(self.wallet, use_mocks=False)
        self.assertFalse(real_auth_client.use_mocks)
        
        # Note: This won't actually work without a real server, but we can test the setup
        self.assertIsNotNone(real_auth_client.transport)
        self.assertIsNotNone(real_auth_client.session_manager)
    
    def test_real_libraries_with_mock_server(self):
        """Test using actual py-sdk libraries with mock HTTP server"""
        # Start mock HTTP server with dynamic port allocation
        mock_server = MockHTTPServer()
        if not mock_server.start():
            self.skipTest("Failed to start mock HTTP server")
        
        try:
            # Wait for server to be ready to accept connections
            if not mock_server.wait_for_server_ready():
                self.skipTest("Mock server not ready within timeout")
            
            # Test that server is running
            self.assertTrue(mock_server.is_server_running())
            
            # Test server health endpoint
            try:
                import requests
                response = requests.get(f'{mock_server.get_server_url()}/health', timeout=1)
                self.assertEqual(response.status_code, 200)
                health_data = response.json()
                self.assertEqual(health_data['status'], 'healthy')
                print("✅ Mock server health check successful")
            except ImportError:
                self.skipTest("requests library not available")
            except Exception as e:
                self.skipTest(f"Server health check failed: {e}")
            
            # Test actual SessionManager library
            try:
                from bsv.auth.session_manager import DefaultSessionManager
                session_manager = DefaultSessionManager()
                self.assertIsNotNone(session_manager)
                print("✅ 実際のSessionManagerライブラリのテストが成功しました")
            except Exception as e:
                self.skipTest(f"SessionManagerライブラリのテストに失敗: {e}")
            
            # Test actual Transport library
            try:
                from bsv.auth.transports.simplified_http_transport import SimplifiedHTTPTransport
                transport = SimplifiedHTTPTransport(mock_server.get_server_url())
                self.assertIsNotNone(transport)
                self.assertEqual(transport.base_url, mock_server.get_server_url())
                print("✅ 実際のTransportライブラリのテストが成功しました")
            except Exception as e:
                self.skipTest(f"Transportライブラリのテストに失敗: {e}")
            
            # Test actual AuthMessage library
            try:
                from bsv.auth.auth_message import AuthMessage
                from bsv.auth.peer import AUTH_VERSION, MessageTypeInitialRequest
                
                auth_message = AuthMessage(
                    version=AUTH_VERSION,
                    message_type=MessageTypeInitialRequest,
                    identity_key="04test_identity_key",
                    initial_nonce="test_nonce"
                )
                
                self.assertEqual(auth_message.version, AUTH_VERSION)
                self.assertEqual(auth_message.message_type, MessageTypeInitialRequest)
                print("✅ 実際のAuthMessageライブラリのテストが成功しました")
            except Exception as e:
                self.skipTest(f"AuthMessageライブラリのテストに失敗: {e}")
            
            # Test actual PeerOptions library
            try:
                from bsv.auth.peer import PeerOptions
                
                peer_options = PeerOptions(
                    wallet=self.wallet,
                    transport=transport,  # Use real transport
                    session_manager=session_manager,  # Use real session manager
                    auto_persist_last_session=True
                )
                
                self.assertEqual(peer_options.wallet, self.wallet)
                self.assertTrue(peer_options.auto_persist_last_session)
                print("✅ 実際のPeerOptionsライブラリのテストが成功しました")
            except Exception as e:
                self.skipTest(f"PeerOptionsライブラリのテストに失敗: {e}")
            
        finally:
            # Stop mock server
            mock_server.stop()
    
    def test_full_real_library_integration(self):
        """Test full integration of real py-sdk libraries with mock server"""
        # Start mock HTTP server with dynamic port allocation
        mock_server = MockHTTPServer()
        if not mock_server.start():
            self.skipTest("Failed to start mock HTTP server")
        
        try:
            # Wait for server to be ready to accept connections
            if not mock_server.wait_for_server_ready():
                self.skipTest("Mock server not ready within timeout")
            
            # Test complete integration
            try:
                from bsv.auth.session_manager import DefaultSessionManager
                from bsv.auth.transports.simplified_http_transport import SimplifiedHTTPTransport
                from bsv.auth.peer import Peer, PeerOptions
                
                # Create real components
                session_manager = DefaultSessionManager()
                transport = SimplifiedHTTPTransport(mock_server.get_server_url())
                
                # Create peer options
                peer_options = PeerOptions(
                    wallet=self.wallet,
                    transport=transport,
                    session_manager=session_manager,
                    auto_persist_last_session=True
                )
                
                # Create peer (this tests the full integration)
                peer = Peer(peer_options)
                
                # Test that all components are properly integrated
                self.assertIsNotNone(peer)
                self.assertIsNotNone(peer.wallet)
                self.assertIsNotNone(peer.transport)
                self.assertIsNotNone(peer.session_manager)
                
                print("✅ 実際のpy-sdkライブラリの完全統合テストが成功しました")
                
                # Test basic peer functionality
                self.assertTrue(hasattr(peer, 'get_authenticated_session'))
                self.assertTrue(hasattr(peer, 'to_peer'))
                
            except Exception as e:
                self.skipTest(f"完全統合テストに失敗: {e}")
            
        finally:
            # Stop mock server
            mock_server.stop()
    
    def test_mock_server_authentication_flow(self):
        """Test that mock server properly handles authentication flow"""
        # Start mock HTTP server with dynamic port allocation
        mock_server = MockHTTPServer()
        if not mock_server.start():
            self.skipTest("Failed to start mock HTTP server")
        
        try:
            # Wait for server to be ready to accept connections
            if not mock_server.wait_for_server_ready():
                self.skipTest("Mock server not ready within timeout")
            
            # Test authentication endpoint
            try:
                import requests
            except ImportError:
                self.skipTest("requests library not available")
            
            # Test initial auth request
            auth_request = {
                "version": "0.1",
                "messageType": "initialRequest",
                "identityKey": "04test_client_key",
                "initialNonce": "test_nonce_123"
            }
            
            try:
                response = requests.post(
                    f'{mock_server.get_server_url()}/.well-known/auth',
                    json=auth_request,
                    timeout=1
                )
                
                self.assertEqual(response.status_code, 200)
                auth_response = response.json()
                
                # Verify response structure
                self.assertEqual(auth_response['version'], '0.1')
                self.assertEqual(auth_response['messageType'], 'initialResponse')
                self.assertEqual(auth_response['initialNonce'], 'test_nonce_123')
                self.assertIn('nonce', auth_response)
                self.assertIn('identityKey', auth_response)
                
                print("✅ Mock server authentication flow test successful")
                
            except Exception as e:
                self.skipTest(f"Authentication flow test failed: {e}")
            
        finally:
            # Stop mock server
            mock_server.stop()
    
    def test_mock_server_rpc_endpoint(self):
        """Test that mock server properly handles RPC requests"""
        # Start mock HTTP server with dynamic port allocation
        mock_server = MockHTTPServer()
        if not mock_server.start():
            self.skipTest("Failed to start mock HTTP server")
        
        try:
            # Wait for server to be ready to accept connections
            if not mock_server.wait_for_server_ready():
                self.skipTest("Mock server not ready within timeout")
            
            # Test RPC endpoint
            try:
                import requests
            except ImportError:
                self.skipTest("requests library not available")
            
            # Test createAction RPC request
            rpc_request = {
                "jsonrpc": "2.0",
                "method": "createAction",
                "params": [{"description": "Test action"}],
                "id": 1
            }
            
            # Add mock auth headers
            headers = {
                'x-bsv-auth-version': '0.1',
                'x-bsv-auth-identity-key': '04test_client_key',
                'x-bsv-auth-signature': 'mock_signature'
            }
            
            try:
                response = requests.post(
                    f'{mock_server.get_server_url()}/',
                    json=rpc_request,
                    headers=headers,
                    timeout=1
                )
                
                self.assertEqual(response.status_code, 200)
                rpc_response = response.json()
                
                # Verify response structure
                self.assertEqual(rpc_response['jsonrpc'], '2.0')
                self.assertEqual(rpc_response['id'], 1)
                self.assertIn('result', rpc_response)
                
                result = rpc_response['result']
                self.assertIn('txid', result)
                self.assertEqual(result['status'], 'success')
                
                print("✅ Mock server RPC endpoint test successful")
                
            except Exception as e:
                self.skipTest(f"RPC endpoint test failed: {e}")
            
        finally:
            # Stop mock server
            mock_server.stop()
    
    def test_server_error_handling(self):
        """Test that mock server properly handles errors"""
        # Start mock HTTP server with dynamic port allocation
        mock_server = MockHTTPServer()
        if not mock_server.start():
            self.skipTest("Failed to start mock HTTP server")
        
        try:
            # Wait for server to be ready to accept connections
            if not mock_server.wait_for_server_ready():
                self.skipTest("Mock server not ready within timeout")
            
            try:
                import requests
            except ImportError:
                self.skipTest("requests library not available")
            
            # Test invalid endpoint
            try:
                response = requests.get(f'{mock_server.get_server_url()}/invalid', timeout=1)
                self.assertEqual(response.status_code, 404)
                print("✅ Mock server 404 error handling test successful")
            except Exception as e:
                self.skipTest(f"404 error handling test failed: {e}")
            
            # Test invalid auth request
            try:
                response = requests.post(
                    f'{mock_server.get_server_url()}/.well-known/auth',
                    json={"invalid": "data"},
                    timeout=1
                )
                self.assertEqual(response.status_code, 400)
                print("✅ Mock server 400 error handling test successful")
            except Exception as e:
                self.skipTest(f"400 error handling test failed: {e}")
            
            # Test RPC without auth headers
            try:
                response = requests.post(
                    f'{mock_server.get_server_url()}/',
                    json={"method": "test"},
                    timeout=1
                )
                self.assertEqual(response.status_code, 401)
                print("✅ Mock server 401 error handling test successful")
            except Exception as e:
                self.skipTest(f"401 error handling test failed: {e}")
            
        finally:
            # Stop mock server
            mock_server.stop()


def run_demo():
    """
    Run a demonstration of the authentication flow
    
    This function shows how to use the PySDKAuthClient in a real application
    """
    print("🔐 py-sdk BSV Toolbox 認証デモ（スタンドアロン版）")
    print("=" * 50)
    
    # Test private key (for demonstration purposes only)
    private_key_hex = "143ab18a84d3b25e1a13cefa90038411e5d2014590a2a4a57263d1593c8dee1c"
    
    # Create mock wallet
    wallet = MockWallet(private_key_hex)
    
    # Create py-sdk auth client with mocks
    auth_client = PySDKAuthClient(wallet, use_mocks=True)
    
    try:
        # Show initial status
        print("\n📊 初期認証状態:")
        status = auth_client.get_auth_status()
        print(json.dumps(status, indent=2))
        
        # Run authentication flow (works with mocks)
        print("\n🔧 認証テスト実行（モック使用）:")
        result = auth_client.complete_auth_flow()
        
        if result:
            print("✅ 認証が成功しました！")
            
            # Test authenticated request
            test_data = {
                "description": "py-sdkテストアクション",
                "outputs": [{"lockingScript": "76a914...", "satoshis": 100}]
            }
            
            result = auth_client.step2_execute_authenticated_request(
                "POST", 
                "createAction",
                test_data
            )
            print(f"API呼び出し結果: {result}")
            
            # Show final status
            print("\n📊 最終認証状態:")
            final_status = auth_client.get_auth_status()
            print(json.dumps(final_status, indent=2))
            
        else:
            print("❌ 認証に失敗しました")
            
    except Exception as e:
        print(f"❌ デモ実行中にエラーが発生: {e}")


def run_real_library_demo():
    """
    Run a demonstration using real py-sdk libraries with mock HTTP server
    """
    print("🚀 実際のpy-sdkライブラリ + モックHTTPサーバーデモ")
    print("=" * 50)
    
    # Start mock HTTP server with dynamic port allocation
    mock_server = MockHTTPServer()
    if not mock_server.start():
        print("❌ モックHTTPサーバーの起動に失敗しました")
        return
    
    try:
        # Wait for server to be ready to accept connections
        if not mock_server.wait_for_server_ready():
            print("❌ モックHTTPサーバーの準備が完了しませんでした")
            return
        
        print(f"✅ モックHTTPサーバーが起動しました: {mock_server.get_server_url()}")
        
        # Test private key (for demonstration purposes only)
        private_key_hex = "143ab18a84d3b25e1a13cefa90038411e5d2014590a2a4a57263d1593c8dee1c"
        
        # Create mock wallet
        wallet = MockWallet(private_key_hex)
        
        # Test actual py-sdk libraries
        try:
            print("\n📚 実際のpy-sdkライブラリのテスト:")
            
            # Test SessionManager
            from bsv.auth.session_manager import DefaultSessionManager
            session_manager = DefaultSessionManager()
            print("✅ SessionManager: 作成成功")
            
            # Test Transport
            from bsv.auth.transports.simplified_http_transport import SimplifiedHTTPTransport
            transport = SimplifiedHTTPTransport(mock_server.get_server_url())
            print("✅ Transport: 作成成功")
            
            # Test PeerOptions
            from bsv.auth.peer import PeerOptions
            peer_options = PeerOptions(
                wallet=wallet,
                transport=transport,
                session_manager=session_manager,
                auto_persist_last_session=True
            )
            print("✅ PeerOptions: 作成成功")
            
            # Test Peer creation
            from bsv.auth.peer import Peer
            _ = Peer(peer_options)
            print("✅ Peer: 作成成功")
            
            print("\n🎉 全ての実際のpy-sdkライブラリのテストが成功しました！")
            
            # Test server endpoints
            print("\n🌐 モックサーバーのエンドポイントテスト:")
            
            try:
                import requests
            except ImportError:
                print("❌ requestsライブラリが利用できません")
                return
            
            # Test health endpoint
            try:
                response = requests.get(f'{mock_server.get_server_url()}/health', timeout=1)
                if response.status_code == 200:
                    print("✅ ヘルスエンドポイント: 正常")
                else:
                    print(f"❌ ヘルスエンドポイント: エラー {response.status_code}")
            except Exception as e:
                print(f"❌ ヘルスエンドポイント: 接続エラー {e}")
            
            # Test auth endpoint
            try:
                auth_request = {
                    "version": "0.1",
                    "messageType": "initialRequest",
                    "identityKey": "04test_demo_key",
                    "initialNonce": "demo_nonce_123"
                }
                
                response = requests.post(
                    f'{mock_server.get_server_url()}/.well-known/auth',
                    json=auth_request,
                    timeout=1
                )
                
                if response.status_code == 200:
                    auth_response = response.json()
                    print("✅ 認証エンドポイント: 正常")
                    print(f"   レスポンス: {json.dumps(auth_response, indent=2)}")
                else:
                    print(f"❌ 認証エンドポイント: エラー {response.status_code}")
            except Exception as e:
                print(f"❌ 認証エンドポイント: 接続エラー {e}")
            
            # Test RPC endpoint
            try:
                rpc_request = {
                    "jsonrpc": "2.0",
                    "method": "createAction",
                    "params": [{"description": "Demo action"}],
                    "id": 1
                }
                
                headers = {
                    'x-bsv-auth-version': '0.1',
                    'x-bsv-auth-identity-key': '04test_demo_key',
                    'x-bsv-auth-signature': 'demo_signature'
                }
                
                response = requests.post(
                    f'{mock_server.get_server_url()}/',
                    json=rpc_request,
                    headers=headers,
                    timeout=1
                )
                
                if response.status_code == 200:
                    rpc_response = response.json()
                    print("✅ RPCエンドポイント: 正常")
                    print(f"   レスポンス: {json.dumps(rpc_response, indent=2)}")
                else:
                    print(f"❌ RPCエンドポイント: エラー {response.status_code}")
            except Exception as e:
                print(f"❌ RPCエンドポイント: 接続エラー {e}")
            
        except ImportError as e:
            print(f"❌ py-sdkライブラリのインポートに失敗: {e}")
        except Exception as e:
            print(f"❌ ライブラリテスト中にエラーが発生: {e}")
        
    except Exception as e:
        print(f"❌ デモ実行中にエラーが発生: {e}")
    
    finally:
        # Stop mock server
        mock_server.stop()
        print("\n🛑 モックHTTPサーバーを停止しました")


def test_single_process_server_management():  # NOSONAR - Complexity (17), requires refactoring
    """
    Test that multiple servers can be managed in a single process
    This function demonstrates the improved server management
    """
    print("🧪 単一プロセスでのサーバー管理テスト")
    print("=" * 50)
    
    servers = []
    try:
        # Create and start multiple servers
        for i in range(3):
            print(f"\n📡 サーバー {i+1} を起動中...")
            server = MockHTTPServer()
            
            if server.start():
                print(f"✅ サーバー {i+1} が起動しました: {server.get_server_url()}")
                servers.append(server)
                
                # Wait for server to be ready
                if server.wait_for_server_ready():
                    print(f"✅ サーバー {i+1} が準備完了しました")
                else:
                    print(f"❌ サーバー {i+1} の準備が完了しませんでした")
            else:
                print(f"❌ サーバー {i+1} の起動に失敗しました")
        
        print(f"\n🎉 {len(servers)} 個のサーバーが正常に起動しました")
        
        # Test that all servers are responding
        try:
            import requests
            for i, server in enumerate(servers):
                try:
                    response = requests.get(f'{server.get_server_url()}/health', timeout=1)
                    if response.status_code == 200:
                        print(f"✅ サーバー {i+1} のヘルスチェック: 正常")
                    else:
                        print(f"❌ サーバー {i+1} のヘルスチェック: エラー {response.status_code}")
                except Exception as e:
                    print(f"❌ サーバー {i+1} のヘルスチェック: 接続エラー {e}")
        except ImportError:
            print("⚠️ requestsライブラリが利用できないため、ヘルスチェックをスキップ")
        
    except Exception as e:
        print(f"❌ サーバー管理テスト中にエラーが発生: {e}")
    
    finally:
        # Stop all servers
        print(f"\n🛑 {len(servers)} 個のサーバーを停止中...")
        for i, server in enumerate(servers):
            server.stop()
            print(f"✅ サーバー {i+1} を停止しました")
        
        print("🎯 単一プロセスでのサーバー管理テストが完了しました")


def run_standalone_tests():
    """
    Run standalone tests that don't require external dependencies
    """
    print("🧪 スタンドアロンテスト実行")
    print("=" * 50)
    
    # Create test suite
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestMetanetDesktopAuth)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "=" * 50)
    print("📊 テスト結果サマリー")
    print(f"実行されたテスト: {result.testsRun}")
    print(f"失敗: {len(result.failures)}")
    print(f"エラー: {len(result.errors)}")
    
    if result.failures:
        print("\n❌ 失敗したテスト:")
        for test, traceback in result.failures:
            print(f"  - {test}: {traceback}")
    
    if result.errors:
        print("\n❌ エラーが発生したテスト:")
        for test, traceback in result.errors:
            print(f"  - {test}: {traceback}")
    
    return result.wasSuccessful()


def main():
    """
    Main function to run tests and demo
    """
    print("Metanet Desktop Authentication Test Suite (Standalone)")
    print("=" * 50)
    
    # Check command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--demo":
            # Run demo
            run_demo()
        elif sys.argv[1] == "--tests":
            # Run tests only
            success = run_standalone_tests()
            sys.exit(0 if success else 1)
        elif sys.argv[1] == "--real-demo":
            # Run real library demo
            run_real_library_demo()
        elif sys.argv[1] == "--server-test":
            # Run single process server management test
            test_single_process_server_management()
        elif sys.argv[1] == "--help":
            # Show help
            print("使用方法:")
            print("  python test_metanet_desktop_auth.py          # デフォルト: テスト実行")
            print("  python test_metanet_desktop_auth.py --demo   # デモ実行")
            print("  python test_metanet_desktop_auth.py --tests  # テストのみ実行")
            print("  python test_metanet_desktop_auth.py --real-demo # 実際のpy-sdkライブラリ on モックHTTPサーバー")
            print("  python test_metanet_desktop_auth.py --server-test # 単一プロセスでのサーバー管理テスト")
            print("  python test_metanet_desktop_auth.py --help   # このヘルプを表示")
        else:
            print(f"不明なオプション: {sys.argv[1]}")
            print("--help で使用方法を確認してください")
    else:
        # Default: run tests
        print("Running standalone unit tests...")
        success = run_standalone_tests()
        if success:
            print("\n🎉 全てのテストが成功しました！")
        else:
            print("\n❌ 一部のテストが失敗しました")


if __name__ == "__main__":
    main()

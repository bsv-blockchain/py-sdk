import pytest
from unittest.mock import Mock
import sys
import os
# Add the bsv directory to Python path to import utils directly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'bsv'))
from auth.utils import get_verifiable_certificates, validate_certificates

class DummyWallet:
    def __init__(self, list_certificates_result=None, prove_certificate_result=None, fail_list=False, fail_prove=False):
        self._list_certificates_result = list_certificates_result or {'certificates': []}
        self._prove_certificate_result = prove_certificate_result or {'keyring_for_verifier': {}}
        self._fail_list = fail_list
        self._fail_prove = fail_prove
        self.list_certificates_called_with = None
        self.prove_certificate_called_with = None
    def list_certificates(self, args):
        self.list_certificates_called_with = args
        if self._fail_list:
            raise RuntimeError('listCertificates failed')
        return self._list_certificates_result
    def prove_certificate(self, args):
        self.prove_certificate_called_with = args
        if self._fail_prove:
            raise RuntimeError('proveCertificate failed')
        return self._prove_certificate_result

class DummyVerifiableCertificate:
    def __init__(self, cert_type=None, serial_number=None, subject=None, certifier=None, 
                 revocation_outpoint=None, fields=None, keyring=None, signature=None, 
                 valid=True, decrypt_ok=True):
        # Accept all parameters from VerifiableCertificate constructor
        self.type = cert_type or 'requested_type'
        self.serial_number = serial_number or 'valid_serial'
        self.subject = subject or 'valid_subject'
        self.certifier = certifier or 'valid_certifier'
        self.revocation_outpoint = revocation_outpoint or 'outpoint'
        self.fields = fields or {}
        self.keyring = keyring or {}
        self.signature = signature or 'signature'
        
        # Test control attributes
        self.valid = valid
        self.decrypt_ok = decrypt_ok
        self.verify_called = False
        self.decrypt_fields_called = False
        
    def verify(self):
        self.verify_called = True
        return self.valid
    def decrypt_fields(self, ctx, wallet):
        self.decrypt_fields_called = True
        if not self.decrypt_ok:
            raise RuntimeError('Decryption failed')
        return {'field1': 'decryptedValue1'}

# Patch VerifiableCertificate to Dummy per test (no cross-module leakage)
import bsv.auth.utils as _au
import bsv.auth.verifiable_certificate as _vcmod

@pytest.fixture(autouse=True)
def _patch_vc(monkeypatch):
    monkeypatch.setattr(_au, 'VerifiableCertificate', DummyVerifiableCertificate, raising=False)
    monkeypatch.setattr(_vcmod, 'VerifiableCertificate', DummyVerifiableCertificate, raising=False)
    yield

def test_get_verifiable_certificates_success():
    wallet = DummyWallet(list_certificates_result={
        'certificates': [{
            'type': 'requested_type',
            'serialNumber': 'valid_serial',
            'subject': 'valid_subject',
            'certifier': 'valid_certifier',
            'revocationOutpoint': 'outpoint',
            'fields': {'field1': 'encryptedData1'},
            'signature': 'signature1'
        }]
    }, prove_certificate_result={'keyring_for_verifier': {'field1': 'key1'}})
    requested = {
        'certifiers': ['valid_certifier'],
        'types': {'requested_type': ['field1']}
    }
    verifier_identity_key = 'verifier_pubkey'
    result = get_verifiable_certificates(wallet, requested, verifier_identity_key)
    assert len(result) == 1
    cert = result[0]
    assert cert.type == 'requested_type'
    assert cert.serial_number == 'valid_serial'
    assert cert.certifier == 'valid_certifier'


def test_get_verifiable_certificates_empty():
    wallet = DummyWallet(list_certificates_result={'certificates': []})
    requested = {'certifiers': [], 'types': {}}
    verifier_identity_key = 'verifier_pubkey'
    result = get_verifiable_certificates(wallet, requested, verifier_identity_key)
    assert result == []


def test_get_verifiable_certificates_list_error():
    wallet = DummyWallet(fail_list=True)
    requested = {'certifiers': [], 'types': {}}
    verifier_identity_key = 'verifier_pubkey'
    with pytest.raises(RuntimeError, match='listCertificates failed'):
        get_verifiable_certificates(wallet, requested, verifier_identity_key)


def test_get_verifiable_certificates_prove_error():
    wallet = DummyWallet(list_certificates_result={
        'certificates': [{
            'type': 'requested_type',
            'serialNumber': 'valid_serial',
            'subject': 'valid_subject',
            'certifier': 'valid_certifier',
            'revocationOutpoint': 'outpoint',
            'fields': {'field1': 'encryptedData1'},
            'signature': 'signature1'
        }]
    }, fail_prove=True)
    requested = {'certifiers': ['valid_certifier'], 'types': {'requested_type': ['field1']}}
    verifier_identity_key = 'verifier_pubkey'
    with pytest.raises(RuntimeError, match='proveCertificate failed'):
        get_verifiable_certificates(wallet, requested, verifier_identity_key)


def test_validate_certificates_success():
    verifier_wallet = Mock()
    message = {
        'identityKey': 'valid_subject',
        'certificates': [{
            'type': 'requested_type',
            'serialNumber': 'valid_serial',
            'subject': 'valid_subject',
            'certifier': 'valid_certifier',
            'revocationOutpoint': 'outpoint',
            'fields': {'field1': 'encryptedData1'},
            'keyring': {},
            'signature': 'signature1'
        }]
    }
    validate_certificates(verifier_wallet, message)


def test_validate_certificates_mismatched_identity():
    verifier_wallet = Mock()
    message = {
        'identityKey': 'different_subject',
        'certificates': [{
            'type': 'requested_type',
            'serialNumber': 'valid_serial',
            'subject': 'valid_subject',
            'certifier': 'valid_certifier',
            'revocationOutpoint': 'outpoint',
            'fields': {'field1': 'encryptedData1'},
            'keyring': {},
            'signature': 'signature1'
        }]
    }
    with pytest.raises(ValueError, match='The subject of one of your certificates'):
        validate_certificates(verifier_wallet, message)


def test_validate_certificates_invalid_signature():
    class InvalidCert(DummyVerifiableCertificate):
        def verify(self):
            return False
    _au.VerifiableCertificate = InvalidCert
    _vcmod.VerifiableCertificate = InvalidCert
    verifier_wallet = Mock()
    message = {
        'identityKey': 'valid_subject',
        'certificates': [{
            'type': 'requested_type',
            'serialNumber': 'valid_serial',
            'subject': 'valid_subject',
            'certifier': 'valid_certifier',
            'revocationOutpoint': 'outpoint',
            'fields': {'field1': 'encryptedData1'},
            'keyring': {},
            'signature': 'signature1'
        }]
    }
    with pytest.raises(ValueError, match='The signature for the certificate with serial number valid_serial is invalid!'):
        validate_certificates(verifier_wallet, message)
    # Restore
    _au.VerifiableCertificate = DummyVerifiableCertificate
    _vcmod.VerifiableCertificate = DummyVerifiableCertificate


def test_validate_certificates_unrequested_certifier():
    verifier_wallet = Mock()
    message = {
        'identityKey': 'valid_subject',
        'certificates': [{
            'type': 'requested_type',
            'serialNumber': 'valid_serial',
            'subject': 'valid_subject',
            'certifier': 'valid_certifier',
            'revocationOutpoint': 'outpoint',
            'fields': {'field1': 'encryptedData1'},
            'keyring': {},
            'signature': 'signature1'
        }]
    }
    certificates_requested = {
        'certifiers': ['another_certifier'],
        'types': {'requested_type': ['field1']}
    }
    with pytest.raises(ValueError, match='has an unrequested certifier'):
        validate_certificates(verifier_wallet, message, certificates_requested)


def test_validate_certificates_unrequested_type():
    verifier_wallet = Mock()
    message = {
        'identityKey': 'valid_subject',
        'certificates': [{
            'type': 'requested_type',
            'serialNumber': 'valid_serial',
            'subject': 'valid_subject',
            'certifier': 'valid_certifier',
            'revocationOutpoint': 'outpoint',
            'fields': {'field1': 'encryptedData1'},
            'keyring': {},
            'signature': 'signature1'
        }]
    }
    certificates_requested = {
        'certifiers': ['valid_certifier'],
        'types': {'another_type': ['field1']}
    }
    with pytest.raises(ValueError, match='was not requested'):
        validate_certificates(verifier_wallet, message, certificates_requested)


def test_validate_certificates_decrypt_error():
    class DecryptFailCert(DummyVerifiableCertificate):
        def decrypt_fields(self, ctx, wallet):
            raise RuntimeError('Decryption failed')
    _au.VerifiableCertificate = DecryptFailCert
    _vcmod.VerifiableCertificate = DecryptFailCert
    verifier_wallet = Mock()
    message = {
        'identityKey': 'valid_subject',
        'certificates': [{
            'type': 'requested_type',
            'serialNumber': 'valid_serial',
            'subject': 'valid_subject',
            'certifier': 'valid_certifier',
            'revocationOutpoint': 'outpoint',
            'fields': {'field1': 'encryptedData1'},
            'keyring': {},
            'signature': 'signature1'
        }]
    }
    with pytest.raises(RuntimeError, match='Decryption failed'):
        validate_certificates(verifier_wallet, message)
    # Restore
    _au.VerifiableCertificate = DummyVerifiableCertificate
    _vcmod.VerifiableCertificate = DummyVerifiableCertificate


def test_validate_certificates_multiple():
    verifier_wallet = Mock()
    message = {
        'identityKey': 'valid_subject',
        'certificates': [
            {
                'type': 'requested_type',
                'serialNumber': 'valid_serial',
                'subject': 'valid_subject',
                'certifier': 'valid_certifier',
                'revocationOutpoint': 'outpoint',
                'fields': {'field1': 'encryptedData1'},
                'keyring': {},
                'signature': 'signature1'
            },
            {
                'type': 'requested_type',
                'serialNumber': 'another_serial',
                'subject': 'valid_subject',
                'certifier': 'valid_certifier',
                'revocationOutpoint': 'outpoint',
                'fields': {'field1': 'encryptedData1'},
                'keyring': {},
                'signature': 'signature2'
            }
        ]
    }
    validate_certificates(verifier_wallet, message)

import pytest
from urllib.parse import urlparse

def to_origin_header(originator: str, scheme_from_base: str) -> str:
    # 厳密なバリデーションを追加
    try:
        if '://' not in originator:
            origin = f"{scheme_from_base}://{originator}"
        else:
            origin = originator
        parsed = urlparse(origin)
        # スキームとホストが両方なければ不正
        if not parsed.scheme or not parsed.hostname:
            raise ValueError('Malformed input')
        if any(c in originator for c in '^% '):
            raise ValueError('Malformed input')
        if parsed.port:
            return f"{parsed.scheme}://{parsed.hostname}:{parsed.port}"
        return f"{parsed.scheme}://{parsed.hostname}"
    except Exception:
        raise ValueError('Malformed input')

@pytest.mark.parametrize("originator, base_url, expected", [
    ("localhost", "https://localhost:3321", "https://localhost"),
    ("localhost:3000", "https://localhost:3321", "https://localhost:3000"),
    ("example.com", "https://api.example.com", "https://example.com"),
    ("https://example.com:8443", "https://localhost:3321", "https://example.com:8443"),
])
def test_to_origin_header_vectors(originator, base_url, expected):
    scheme_from_base = urlparse(base_url).scheme
    result = to_origin_header(originator, scheme_from_base)
    assert result == expected

def test_to_origin_header_malformed():
    with pytest.raises(ValueError):
        to_origin_header("bad url^%", "http")

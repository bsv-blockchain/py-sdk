import pytest
from unittest.mock import patch
from bsv.totp import TOTP


# Test data matching TS SDK exactly
secret = bytes.fromhex('48656c6c6f21deadbeef')
period = 30  # seconds
period_ms = 30 * 1000  # milliseconds
options = {
    'digits': 6,
    'period': period,
    'algorithm': 'SHA-1'
}


class TestTOTPGenerationAndValidation:
    """Test TOTP generation and validation matching TS SDK tests exactly."""

    @pytest.mark.parametrize("time_ms,expected,description", [
        (0, '282760', 'should generate token at Unix epoch start'),
        (1465324707000, '341128', 'should generate token for a specific timestamp in 2016'),
        (1665644340000 + 1, '886842', 'should generate correct token at the start of the cycle'),
        (1665644340000 - 1, '134996', 'should generate correct token at the end of the cycle'),
        (1365324707000, '089029', 'should generate token with a leading zero'),
    ])
    def test_totp_generation_and_validation(self, time_ms, expected, description):
        """Test TOTP generation and validation for various timestamps."""
        # Patch time in the totp module
        with patch('bsv.totp.totp.time.time', return_value=time_ms / 1000.0):
            # Check if expected passcode is generated
            passcode = TOTP.generate(secret, options)
            assert passcode == expected, f"Failed for {description}"

            # This passcode should not be valid for any of above test cases
            assert TOTP.validate(secret, '000000', options) is False

            # Should not be valid for only a part of passcode
            assert TOTP.validate(secret, passcode[1:], options) is False

            assert TOTP.validate(secret, passcode, options) is True

            def check_adjacent_window(time_of_generation_ms, expected_result):
                """Helper to check adjacent time windows."""
                with patch('bsv.totp.totp.time.time', return_value=time_of_generation_ms / 1000.0):
                    adjacent_timewindow_passcode = TOTP.generate(secret, options)

                with patch('bsv.totp.totp.time.time', return_value=time_ms / 1000.0):
                    result = TOTP.validate(secret, adjacent_timewindow_passcode, options)
                    assert result == expected_result

            # Because the 'skew' is '1' by default, the passcode for the next window also should be valid
            check_adjacent_window(time_ms + period_ms, True)
            check_adjacent_window(time_ms - period_ms, True)

            # For 'skew': 1, other passcodes for further timewindows should not be valid
            for i in range(2, 10):
                check_adjacent_window(time_ms + i * period_ms, False)
                check_adjacent_window(time_ms - i * period_ms, False)


from bsv.script.interpreter.config import AfterGenesisConfig, BeforeGenesisConfig


def test_max_script_number_length_after_genesis_is_32mb():
    config = AfterGenesisConfig()
    assert config.max_script_number_length() == 32 * 1000 * 1000


def test_before_genesis_limit_unchanged():
    config = BeforeGenesisConfig()
    assert config.max_script_number_length() == 4

from dataclasses import dataclass, field
from typing import Optional

@dataclass
class DisplayableIdentity:
    name: str = "Unknown Identity"
    avatar_url: str = "XUUB8bbn9fEthk15Ge3zTQXypUShfC94vFjp65v7u5CQ8qkpxzst"
    abbreviated_key: str = ""
    identity_key: str = ""
    badge_icon_url: str = "XUUV39HVPkpmMzYNTx7rpKzJvXfeiVyQWg2vfSpjBAuhunTCA9uG"
    badge_label: str = "Not verified by anyone you trust."
    badge_click_url: str = "https://projectbabbage.com/docs/unknown-identity"

# Used as default value
DefaultIdentity = DisplayableIdentity()

@dataclass
class IdentityClientOptions:
    protocol_id: Optional[dict] = field(default_factory=dict)  # Corresponds to wallet.Protocol
    key_id: str = "1"
    token_amount: int = 1
    output_index: int = 0

class KnownIdentityTypes:  # NOSONAR - PascalCase constants match TS/Go SDK identity certificate types
    IdentiCert  = "z40BOInXkI8m7f/wBrv4MJ09bZfzZbTj2fJqCtONqCY="
    DiscordCert = "2TgqRC35B1zehGmB21xveZNc7i5iqHc0uxMb+1NMPW4="
    PhoneCert   = "mffUklUzxbHr65xLohn0hRL0Tq2GjW1GYF/OPfzqJ6A="
    XCert       = "vdDWvftf1H+5+ZprUw123kjHlywH+v20aPQTuXgMpNc="
    Registrant  = "YoPsbfR6YQczjzPdHCoGC7nJsOdPQR50+SYqcWpJ0y0="
    EmailCert   = "exOl3KM0dIJ04EW5pZgbZmPag6MdJXd3/a1enmUU/BA="
    Anyone      = "mfkOMfLDQmrr3SBxBQ5WeE+6Hy3VJRFq6w4A5Ljtlis="
    Self        = "Hkge6X5JRxt1cWXtHLCrSTg6dCVTxjQJJ48iOYd7n3g="
    CoolCert    = "AGfk/WrT1eBDXpz3mcw386Zww2HmqcIn3uY6x4Af1eo="

# Type aliases
CertificateFieldNameUnder50Bytes = str
OriginatorDomainNameStringUnder250Bytes = str

# KyoRox Python 3 SAML-to-JWT Verification Example

Standard-library Python 3 (`hmac`, `hashlib`, `base64`, `json`) reference implementation for verifying incoming `HS256` JWT assertions from **[KyoRox Stateless SAML 2.0 Proxy](https://kyorox.com)**.

```python
import base64
import hashlib
import hmac
import json
import time

def _b64url_decode(data: str) -> bytes:
    padding = '=' * (4 - (len(data) % 4)) if len(data) % 4 else ''
    return base64.urlsafe_b64decode(data + padding)

def verify_kyorox_jwt(token: str, client_secret: str, expected_tenant_id: str = None) -> dict:
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Malformed KyoRox JWT structure.")

    header_b64, payload_b64, signature_b64 = parts
    header = json.loads(_b64url_decode(header_b64).decode('utf-8'))
    if header.get("alg") != "HS256":
        raise ValueError("Invalid JWT algorithm; expected HS256.")

    signing_input = f"{header_b64}.{payload_b64}".encode('ascii')
    expected_sig = hmac.new(client_secret.encode('utf-8'), signing_input, hashlib.sha256).digest()
    actual_sig = _b64url_decode(signature_b64)

    if not hmac.compare_digest(actual_sig, expected_sig):
        raise ValueError("Invalid KyoRox HMAC-SHA256 signature.")

    claims = json.loads(_b64url_decode(payload_b64).decode('utf-8'))
    if "exp" in claims and int(time.time()) >= int(claims["exp"]):
        raise ValueError("Expired KyoRox SSO token.")

    if expected_tenant_id and claims.get("tenantId") != expected_tenant_id:
        raise ValueError("Tenant UUID mismatch.")

    return claims
```

## Documentation & Support

* **Website:** [https://kyorox.com](https://kyorox.com)
* **6-IdP Docs (Okta, Entra ID, Google Workspace, JumpCloud, PingIdentity):** [https://kyorox.com/docs](https://kyorox.com/docs)
* **Trust Center:** [https://kyorox.com/trust](https://kyorox.com/trust)
* **Support Desk:** `support@kyorox.com`

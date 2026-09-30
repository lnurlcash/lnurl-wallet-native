"""Run the real lnurl-mint server over its own test suite's FakeNode, so the
wallet can be driven end to end with no Lightning node. Dev only: adds
/_dev/issue?amount=, /_dev/invoice?amount=, /_dev/settle?pr= and
/_dev/fail_payments?on= hooks.

    cd ../lnurl-mint && uv run python ../lnurl-wallet-native/dev/reference-mint.py 8977
"""
import os, sys
from hashlib import sha256

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8977
sys.path.insert(0, os.environ.get("LNURL_MINT_DIR", "../lnurl-mint"))
import tests.conftest as c  # sets DATABASE_PATH etc. before settings load

import httpx
import uvicorn
import lnurl_mint.node as node_module
import lnurl_mint.router as router_module
import lnurl_mint.signing as signing_module
from lnurl_mint.config import settings
from lnurl_mint.server import app

settings.base_url = f"http://127.0.0.1:{PORT}"
fake = c.FakeNode()
settings.fundingsource_backend = "lnd"
for name in ["create_invoice", "is_invoice_settled", "invoice_preimage", "pay_invoice",
             "is_payment_complete", "payment_preimage"]:
    setattr(router_module, name, getattr(fake, name))
node_module.fetch_node_info = fake.fetch_node_info
node_module._node_info_cache = None
router_module._CONFIRMATION_RETRY_DELAYS_SECONDS = ()
signing_module.fetch_node_info = fake.fetch_node_info
signing_module.sign_message = fake.sign_message

@app.get("/_dev/issue")
async def issue(amount: int):
    secret = os.urandom(32)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=settings.base_url) as client:
        r = await client.get(f"/p/cb?amount={amount}&comment={sha256(secret).hexdigest()}")
        assert r.json().get("pr"), r.text
    fake.settled.add(sha256(fake.last_preimage).hexdigest())
    return {"note": f"{settings.base_url}/w?k1={secret.hex()}", "mintPubkey": fake.pubkey}

@app.get("/_dev/invoice")
async def invoice(amount: int):
    return {"pr": c.fake_invoice(amount)}

@app.get("/_dev/settle")
async def settle(pr: str):
    """Mark an invoice this mint issued as paid, as a payer's wallet would."""
    import bolt11
    fake.settled.add(bolt11.decode(pr).payment_hash)
    return {"ok": True}

@app.get("/_dev/fail_payments")
async def fail_payments(on: bool):
    fake.fail_reason = "no route" if on else None
    return {"ok": True}

# a route FastAPI registers after the app's catch-alls might be shadowed; move ours first
for _ in range(4):
    app.router.routes.insert(0, app.router.routes.pop())
uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")

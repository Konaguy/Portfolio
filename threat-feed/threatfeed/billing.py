"""
Stripe subscription billing for the Pro tier.

Upgrade flow: POST /api/billing/checkout -> Stripe Checkout (hosted page,
so card data never touches this server) -> Stripe calls our webhook ->
we flip the user's tier. The tier is changed ONLY by a signature-verified
webhook, never by the browser's return to success_url, which anyone can
visit.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time

import httpx

STRIPE_API = "https://api.stripe.com/v1"
SIGNATURE_TOLERANCE_SECONDS = 300
ACTIVE_STATUSES = {"active", "trialing", "past_due"}  # past_due keeps access during dunning retries


class SignatureError(ValueError):
    pass


def verify_stripe_signature(payload: bytes, header: str, secret: str, now: float | None = None) -> dict:
    """Implements Stripe's documented v1 scheme: HMAC-SHA256 over 't.payload'."""
    if not secret:
        raise SignatureError("webhook secret not configured")
    parts: dict[str, list[str]] = {}
    for item in header.split(","):
        k, _, v = item.strip().partition("=")
        parts.setdefault(k, []).append(v)
    try:
        ts = int(parts["t"][0])
    except (KeyError, ValueError) as e:
        raise SignatureError("missing timestamp") from e
    if abs((now or time.time()) - ts) > SIGNATURE_TOLERANCE_SECONDS:
        raise SignatureError("timestamp outside tolerance (possible replay)")
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    if not any(hmac.compare_digest(expected, sig) for sig in parts.get("v1", [])):
        raise SignatureError("signature mismatch")
    return json.loads(payload)


async def create_checkout_session(client: httpx.AsyncClient, *, secret_key: str, price_id: str, user_id: int,
                                  email: str, customer_id: str | None, base_url: str) -> str:
    data = {
        "mode": "subscription",
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "client_reference_id": str(user_id),
        "metadata[user_id]": str(user_id),
        "subscription_data[metadata][user_id]": str(user_id),
        "success_url": f"{base_url}/?upgraded=1",
        "cancel_url": f"{base_url}/?canceled=1",
        "allow_promotion_codes": "true",
    }
    if customer_id:
        data["customer"] = customer_id
    else:
        data["customer_email"] = email
    r = await client.post(f"{STRIPE_API}/checkout/sessions", data=data, auth=(secret_key, ""))
    r.raise_for_status()
    return r.json()["url"]


async def create_portal_session(client: httpx.AsyncClient, *, secret_key: str, customer_id: str,
                                base_url: str) -> str:
    """Stripe-hosted page for the customer to update card / cancel."""
    r = await client.post(f"{STRIPE_API}/billing_portal/sessions",
                          data={"customer": customer_id, "return_url": base_url}, auth=(secret_key, ""))
    r.raise_for_status()
    return r.json()["url"]


def apply_event(store, event: dict) -> str:
    """Map a verified Stripe event onto a tier change. Returns what happened."""
    if not store.mark_webhook_processed(event["id"]):
        return "duplicate"
    etype = event["type"]
    obj = event["data"]["object"]

    if etype == "checkout.session.completed":
        uid = obj.get("client_reference_id") or (obj.get("metadata") or {}).get("user_id")
        if not uid or not store.user_by_id(int(uid)):
            return "unknown-user"
        store.set_tier(int(uid), "pro", obj.get("customer"), obj.get("subscription"))
        return "upgraded"

    if etype in {"customer.subscription.updated", "customer.subscription.deleted"}:
        user = store.user_by_stripe_customer(obj.get("customer", ""))
        if user is None:
            return "unknown-customer"
        active = etype == "customer.subscription.updated" and obj.get("status") in ACTIVE_STATUSES
        store.set_tier(user["id"], "pro" if active else "free", subscription_id=obj.get("id"))
        if not active:
            # Downgrade revokes Pro-only credentials immediately.
            store.delete_api_keys(user["id"])
        return "upgraded" if active else "downgraded"

    return "ignored"

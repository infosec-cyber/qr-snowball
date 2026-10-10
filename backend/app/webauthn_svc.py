"""WebAuthn / passkey ceremonies (py_webauthn). Discoverable credentials so login
needs no username. The PRF extension used for E2E key wrapping is handled entirely
client-side; the server performs standard WebAuthn only.

RP id and origin are passed in per-request (derived from the Host header) so the
same code works on localhost and on any Vercel domain with no env tuning."""
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
import json

RP_NAME = "Relay"


def registration_options(user_id: str, user_name: str, rp_id: str):
    opts = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=user_id.encode(),
        user_name=user_name,
        user_display_name=user_name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            user_verification=UserVerificationRequirement.PREFERRED,
        ),
    )
    return json.loads(options_to_json(opts)), bytes_to_base64url(opts.challenge)


def verify_registration(credential: dict, expected_challenge_b64: str, rp_id: str, origin: str):
    v = verify_registration_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(expected_challenge_b64),
        expected_origin=origin,
        expected_rp_id=rp_id,
        require_user_verification=False,
    )
    return {
        "credential_id": bytes_to_base64url(v.credential_id),
        "public_key": v.credential_public_key,
        "sign_count": v.sign_count,
    }


def authentication_options(rp_id: str):
    opts = generate_authentication_options(
        rp_id=rp_id,
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return json.loads(options_to_json(opts)), bytes_to_base64url(opts.challenge)


def verify_authentication(credential: dict, expected_challenge_b64: str,
                          public_key: bytes, sign_count: int, rp_id: str, origin: str):
    v = verify_authentication_response(
        credential=credential,
        expected_challenge=base64url_to_bytes(expected_challenge_b64),
        expected_origin=origin,
        expected_rp_id=rp_id,
        credential_public_key=public_key,
        credential_current_sign_count=sign_count,
        require_user_verification=False,
    )
    return {"new_sign_count": v.new_sign_count}


def credential_id_from(credential: dict) -> str:
    # The client sends the assertion; `id` is the base64url credential id.
    return credential["id"]

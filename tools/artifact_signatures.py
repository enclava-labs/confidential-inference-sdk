"""Shared Ed25519 artifact-signature verification for offline Python tools."""

from __future__ import annotations

import base64
import binascii
import hashlib
from dataclasses import dataclass
from typing import Mapping, Sequence


BASE64URL_PREFIX = "base64url:"
BASE64URL_NO_PAD_ALPHABET = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
)
ED25519_PUBLIC_KEY_BYTE_LEN = 32
ED25519_SIGNATURE_BYTE_LEN = 64

ED25519_P = 2**255 - 19
ED25519_Q = 2**252 + 27742317777372353535851937790883648493
ED25519_D = (-121665 * pow(121666, ED25519_P - 2, ED25519_P)) % ED25519_P
ED25519_I = pow(2, (ED25519_P - 1) // 4, ED25519_P)
ED25519_BASE_X = (
    15112221349535400772501151409588531511454012693041857206046113283949847762202
)
ED25519_BASE_Y = (
    46316835694926478169428394003475163141307993866256225615783033603165251855960
)

Point = tuple[int, int, int, int]
ED25519_IDENTITY: Point = (0, 1, 1, 0)
ED25519_BASE_POINT: Point = (
    ED25519_BASE_X,
    ED25519_BASE_Y,
    1,
    (ED25519_BASE_X * ED25519_BASE_Y) % ED25519_P,
)


class ArtifactSignatureError(ValueError):
    """Raised when a signed artifact envelope fails signature verification."""


@dataclass(frozen=True)
class TrustedSigningKey:
    signer: str
    key_id: str
    public_key_base64url: str


DEFAULT_TRUSTED_SIGNING_KEYS: tuple[TrustedSigningKey, ...] = (
    TrustedSigningKey(
        signer="confidential-inference",
        key_id="confidential-inference-demo-ed25519-2026",
        public_key_base64url="4oqJcHUzMr1y_vQT5rCy7xtKrdp6osFB8jNxKmh2s1E",
    ),
    TrustedSigningKey(
        signer="confidential-inference",
        key_id="confidential-inference-phase2-fixture-ed25519-2026",
        public_key_base64url="cN-eInmtvsbRK_KSEYTJIi6yTthSAFv2QBOfUuWc2a4",
    ),
    TrustedSigningKey(
        signer="confidential-inference",
        key_id="confidential-inference-compatibility-fixture-ed25519-2026",
        public_key_base64url="bjLBl0Hwr4JgYSrpn9E9ijiURyLgiWTdI5c49VKmFTs",
    ),
    TrustedSigningKey(
        signer="confidential-inference",
        key_id="confidential-inference-alias-matrix-fixture-ed25519-2026",
        public_key_base64url="zxs36F3ACu6U8QEIs38VHio3s64qDK53Uh-DSI25xNc",
    ),
)


def verify_artifact_signature(
    signature: Mapping[str, str],
    message: bytes,
    subject: str,
    trusted_signing_keys: Sequence[TrustedSigningKey] = DEFAULT_TRUSTED_SIGNING_KEYS,
) -> None:
    if signature.get("alg") != "ed25519":
        raise ArtifactSignatureError(f"{subject} signature alg must be ed25519")

    signing_key = _trusted_signing_key(signature, trusted_signing_keys)
    if signing_key is None:
        raise ArtifactSignatureError(
            f"{subject} signature uses unknown signing key "
            f"signer={signature.get('signer')!r} key_id={signature.get('key_id')!r}"
        )

    public_key = _decode_unpadded_base64url(
        signing_key.public_key_base64url,
        f"{subject} trusted public key",
        expected_len=ED25519_PUBLIC_KEY_BYTE_LEN,
    )
    value = signature.get("value", "")
    if not isinstance(value, str):
        raise ArtifactSignatureError(f"{subject} signature value must be a string")
    signature_bytes = _decode_unpadded_base64url(
        value,
        f"{subject} signature value",
        expected_len=ED25519_SIGNATURE_BYTE_LEN,
    )

    if not _ed25519_verify(signature_bytes, public_key, message):
        raise ArtifactSignatureError(f"{subject} signature is invalid")


def encode_unpadded_base64url(value: bytes) -> str:
    return base64.b64encode(value, altchars=b"-_").decode("ascii").rstrip("=")


def decode_unpadded_base64url(
    value: str,
    subject: str,
    *,
    expected_len: int,
) -> bytes:
    return _decode_unpadded_base64url(value, subject, expected_len=expected_len)


def ed25519_public_key_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ArtifactSignatureError("ed25519 seed must be 32 bytes")
    scalar = _secret_scalar(seed)
    return _encode_point(_scalar_mult(ED25519_BASE_POINT, scalar))


def sign_ed25519(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise ArtifactSignatureError("ed25519 seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = _prune_scalar(digest[:32])
    prefix = digest[32:]
    public_key = _encode_point(_scalar_mult(ED25519_BASE_POINT, scalar))
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % ED25519_Q
    encoded_r = _encode_point(_scalar_mult(ED25519_BASE_POINT, r))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_r + public_key + message).digest(),
        "little",
    ) % ED25519_Q
    s = (r + challenge * scalar) % ED25519_Q
    return encoded_r + s.to_bytes(32, "little")


def _trusted_signing_key(
    signature: Mapping[str, str],
    trusted_signing_keys: Sequence[TrustedSigningKey],
) -> TrustedSigningKey | None:
    for key in trusted_signing_keys:
        if signature.get("signer") == key.signer and signature.get("key_id") == key.key_id:
            return key
    return None


def _decode_unpadded_base64url(value: str, subject: str, *, expected_len: int) -> bytes:
    encoded = value[len(BASE64URL_PREFIX) :] if value.startswith(BASE64URL_PREFIX) else value
    if (
        not encoded
        or "=" in encoded
        or any(character not in BASE64URL_NO_PAD_ALPHABET for character in encoded)
        or len(encoded) % 4 == 1
    ):
        raise ArtifactSignatureError(f"{subject} is not unpadded base64url")
    padded = encoded + ("=" * ((4 - len(encoded) % 4) % 4))
    try:
        decoded = base64.b64decode(padded, altchars=b"-_", validate=True)
    except binascii.Error as error:
        raise ArtifactSignatureError(f"{subject} is not base64url: {error}") from error
    if len(decoded) != expected_len:
        raise ArtifactSignatureError(f"{subject} must be {expected_len} bytes")
    return decoded


def _secret_scalar(seed: bytes) -> int:
    return _prune_scalar(hashlib.sha512(seed).digest()[:32])


def _prune_scalar(first_half: bytes) -> int:
    scalar = bytearray(first_half)
    scalar[0] &= 248
    scalar[31] &= 63
    scalar[31] |= 64
    return int.from_bytes(scalar, "little")


def _ed25519_verify(signature: bytes, public_key: bytes, message: bytes) -> bool:
    if len(signature) != ED25519_SIGNATURE_BYTE_LEN:
        return False
    if len(public_key) != ED25519_PUBLIC_KEY_BYTE_LEN:
        return False

    try:
        r = _decode_point(signature[:32])
        a = _decode_point(public_key)
    except ArtifactSignatureError:
        return False

    s = int.from_bytes(signature[32:], "little")
    if s >= ED25519_Q:
        return False

    h = int.from_bytes(
        hashlib.sha512(signature[:32] + public_key + message).digest(),
        "little",
    ) % ED25519_Q

    left = _scalar_mult(ED25519_BASE_POINT, s)
    right = _point_add(r, _scalar_mult(a, h))
    return _points_equal(left, right)


def _decode_point(encoded: bytes) -> Point:
    if len(encoded) != ED25519_PUBLIC_KEY_BYTE_LEN:
        raise ArtifactSignatureError("ed25519 point must be 32 bytes")
    compressed = int.from_bytes(encoded, "little")
    y = compressed & ((1 << 255) - 1)
    sign = compressed >> 255
    if y >= ED25519_P:
        raise ArtifactSignatureError("ed25519 point y-coordinate is not canonical")

    yy = (y * y) % ED25519_P
    xx = ((yy - 1) * pow(ED25519_D * yy + 1, ED25519_P - 2, ED25519_P)) % ED25519_P
    if xx == 0:
        if sign:
            raise ArtifactSignatureError("ed25519 point has invalid sign bit")
        x = 0
    else:
        x = pow(xx, (ED25519_P + 3) // 8, ED25519_P)
        if (x * x - xx) % ED25519_P != 0:
            x = (x * ED25519_I) % ED25519_P
        if (x * x - xx) % ED25519_P != 0:
            raise ArtifactSignatureError("ed25519 point is not on the curve")
        if (x & 1) != sign:
            x = ED25519_P - x

    if not _is_on_curve(x, y):
        raise ArtifactSignatureError("ed25519 point is not on the curve")
    return (x, y, 1, (x * y) % ED25519_P)


def _encode_point(point: Point) -> bytes:
    x, y, z, _ = point
    z_inverse = pow(z, ED25519_P - 2, ED25519_P)
    affine_x = (x * z_inverse) % ED25519_P
    affine_y = (y * z_inverse) % ED25519_P
    encoded = bytearray(affine_y.to_bytes(32, "little"))
    encoded[31] |= (affine_x & 1) << 7
    return bytes(encoded)


def _is_on_curve(x: int, y: int) -> bool:
    xx = (x * x) % ED25519_P
    yy = (y * y) % ED25519_P
    return (yy - xx - 1 - ED25519_D * xx * yy) % ED25519_P == 0


def _point_add(left: Point, right: Point) -> Point:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = ((y1 - x1) * (y2 - x2)) % ED25519_P
    b = ((y1 + x1) * (y2 + x2)) % ED25519_P
    c = (2 * ED25519_D * t1 * t2) % ED25519_P
    d = (2 * z1 * z2) % ED25519_P
    e = (b - a) % ED25519_P
    f = (d - c) % ED25519_P
    g = (d + c) % ED25519_P
    h = (b + a) % ED25519_P
    return (
        (e * f) % ED25519_P,
        (g * h) % ED25519_P,
        (f * g) % ED25519_P,
        (e * h) % ED25519_P,
    )


def _scalar_mult(point: Point, scalar: int) -> Point:
    result = ED25519_IDENTITY
    addend = point
    while scalar > 0:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _points_equal(left: Point, right: Point) -> bool:
    x1, y1, z1, _ = left
    x2, y2, z2, _ = right
    return (x1 * z2 - x2 * z1) % ED25519_P == 0 and (
        y1 * z2 - y2 * z1
    ) % ED25519_P == 0

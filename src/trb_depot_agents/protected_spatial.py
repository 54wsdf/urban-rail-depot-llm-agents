from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .integrity import sha256_digest, stable_json
from .spatial import SpatialModel


class KeyProvider(Protocol):
    def key_for(self, key_id: str) -> bytes:
        ...


class EnvKeyProvider:
    def __init__(self, environ: dict[str, str] | None = None, prefix: str = "TRB_SPATIAL_KEY_") -> None:
        import os

        self.environ = environ if environ is not None else os.environ
        self.prefix = prefix

    def key_for(self, key_id: str) -> bytes:
        value = self.environ.get(f"{self.prefix}{key_id}")
        if not value:
            raise KeyError(f"Missing protected spatial key for key_id={key_id!r}")
        try:
            key = base64.b64decode(value, validate=True)
        except ValueError as exc:
            raise ValueError("Protected spatial keys must use strict base64 encoding") from exc
        if len(key) != 32:
            raise ValueError("AES-256-GCM protected spatial keys must contain 32 bytes")
        return key


@dataclass(frozen=True)
class ProtectedSpatialEnvelope:
    bundle_id: str
    key_id: str
    algorithm: str
    nonce_b64: str
    ciphertext_b64: str
    plaintext_sha256: str
    aad: str = "trb-depot-agents/spatial-bundle/v1"

    @classmethod
    def from_dict(cls, payload: dict) -> "ProtectedSpatialEnvelope":
        return cls(
            bundle_id=str(payload["bundle_id"]),
            key_id=str(payload["key_id"]),
            algorithm=str(payload.get("algorithm", "AES-256-GCM")),
            nonce_b64=str(payload["nonce_b64"]),
            ciphertext_b64=str(payload["ciphertext_b64"]),
            plaintext_sha256=str(payload["plaintext_sha256"]),
            aad=str(payload.get("aad", "trb-depot-agents/spatial-bundle/v1")),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "bundle_id": self.bundle_id,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "nonce_b64": self.nonce_b64,
            "ciphertext_b64": self.ciphertext_b64,
            "plaintext_sha256": self.plaintext_sha256,
            "aad": self.aad,
        }

    def authenticated_data(self) -> bytes:
        # 防退化：bundle 标识、密钥标识、算法和明文摘要都必须进入 AAD，不能只加密正文而允许替换 envelope 元数据。
        return stable_json(
            {
                "aad": self.aad,
                "algorithm": self.algorithm,
                "bundle_id": self.bundle_id,
                "key_id": self.key_id,
                "plaintext_sha256": self.plaintext_sha256,
            }
        ).encode("utf-8")


class AesGcmCodec:
    @staticmethod
    def _aesgcm():
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:
            raise RuntimeError(
                "cryptography is required for protected spatial bundles; install it or pass a public synthetic spatial_model"
            ) from exc
        return AESGCM

    def encrypt(self, plaintext: bytes, *, key: bytes, nonce: bytes, aad: bytes) -> bytes:
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte key")
        if len(nonce) != 12:
            raise ValueError("AES-GCM envelopes require a 12-byte nonce")
        return self._aesgcm()(key).encrypt(nonce, plaintext, aad)

    def decrypt(self, envelope: ProtectedSpatialEnvelope, key_provider: KeyProvider) -> bytes:
        if envelope.algorithm != "AES-256-GCM":
            # 防退化：保护包算法必须固定到带明确密钥长度的 AES-256-GCM，不能接受含义模糊的别名。
            raise ValueError(f"Unsupported protected spatial algorithm: {envelope.algorithm}")
        key = key_provider.key_for(envelope.key_id)
        if len(key) != 32:
            raise ValueError("AES-256-GCM protected spatial keys must contain 32 bytes")
        nonce = base64.b64decode(envelope.nonce_b64, validate=True)
        ciphertext = base64.b64decode(envelope.ciphertext_b64, validate=True)
        if len(nonce) != 12:
            raise ValueError("protected spatial nonce must contain 12 bytes")
        plaintext = self._aesgcm()(key).decrypt(
            nonce,
            ciphertext,
            envelope.authenticated_data(),
        )
        digest = sha256_digest(json.loads(plaintext.decode("utf-8")))
        if digest != envelope.plaintext_sha256:
            raise ValueError("protected spatial bundle digest mismatch")
        return plaintext


class ProtectedSpatialBundleLoader:
    def __init__(self, key_provider: KeyProvider | None = None, codec: AesGcmCodec | None = None) -> None:
        self.key_provider = key_provider or EnvKeyProvider()
        self.codec = codec or AesGcmCodec()

    def load(self, source: str | Path | dict) -> SpatialModel:
        if isinstance(source, (str, Path)):
            payload = json.loads(Path(source).read_text(encoding="utf-8"))
        else:
            payload = dict(source)
        envelope = ProtectedSpatialEnvelope.from_dict(payload)
        plaintext = self.codec.decrypt(envelope, self.key_provider)
        # 防退化：真实拓扑只能从加密 envelope 注入，代码库不得写入现场咽喉和道岔规则。
        return SpatialModel.from_dict(json.loads(plaintext.decode("utf-8")))

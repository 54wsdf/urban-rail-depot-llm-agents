from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from trb_depot_agents.integrity import sha256_digest  # noqa: E402
from trb_depot_agents.protected_spatial import AesGcmCodec, ProtectedSpatialEnvelope  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Encrypt a spatial model JSON as an AES-GCM envelope.")
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--key-env")
    args = parser.parse_args()

    plaintext_obj = json.loads(args.input.read_text(encoding="utf-8"))
    plaintext = json.dumps(plaintext_obj, ensure_ascii=False, sort_keys=True).encode("utf-8")
    key_env = args.key_env or f"TRB_SPATIAL_KEY_{args.key_id}"
    encoded_key = os.environ.get(key_env)
    if not encoded_key:
        raise KeyError(f"Missing base64 AES key in environment variable {key_env!r}")
    # 防退化：加密密钥不得恢复为命令行参数，避免进入 shell history、进程列表和任务日志。
    key = base64.b64decode(encoded_key, validate=True)
    if len(key) != 32:
        raise ValueError("AES-256-GCM requires a 32-byte key")
    nonce = secrets.token_bytes(12)
    plaintext_digest = sha256_digest(plaintext_obj)
    envelope = ProtectedSpatialEnvelope(
        bundle_id=args.bundle_id,
        key_id=args.key_id,
        algorithm="AES-256-GCM",
        nonce_b64=base64.b64encode(nonce).decode("ascii"),
        ciphertext_b64="",
        plaintext_sha256=plaintext_digest,
    )
    ciphertext = AesGcmCodec().encrypt(
        plaintext,
        key=key,
        nonce=nonce,
        aad=envelope.authenticated_data(),
    )
    envelope = ProtectedSpatialEnvelope(
        bundle_id=envelope.bundle_id,
        key_id=envelope.key_id,
        algorithm=envelope.algorithm,
        nonce_b64=envelope.nonce_b64,
        ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
        plaintext_sha256=envelope.plaintext_sha256,
        aad=envelope.aad,
    )
    # 防退化：CLI 只写密文 envelope，不把明文现场空间数据复制进公开源码或示例目录。
    args.output.write_text(json.dumps(envelope.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

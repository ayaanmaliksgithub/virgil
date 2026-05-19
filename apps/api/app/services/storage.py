"""S3 / MinIO storage adapter.

Same client code for both environments. Locally, `docker-compose` provisions
a MinIO instance and we point S3_ENDPOINT at it. In production the same env
vars target real S3 (S3_ENDPOINT unset).

Conventions:
  - Bucket layout: `reports/<audit_id>/<view>.<ext>`
  - Returned URI is always `s3://<bucket>/<key>` regardless of endpoint.
  - The bucket is auto-created on first write so a fresh deploy doesn't fail.

This module is intentionally tiny — boto3 is the actual interface; we don't
re-implement signing, retries, or multipart.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from functools import lru_cache
from typing import Literal

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from app.config import get_settings

log = logging.getLogger(__name__)

ReportView = Literal["executive", "technical", "sbom"]
ReportFormat = Literal["json", "md", "pdf", "cyclonedx", "spdx"]


@dataclass
class StoredObject:
    uri: str         # s3://bucket/key — canonical, persisted on the Report row
    key: str         # bucket-relative key
    bucket: str
    presigned_url: str | None = None


@lru_cache(maxsize=1)
def _client():
    s = get_settings()
    cfg = Config(signature_version="s3v4", retries={"max_attempts": 3, "mode": "standard"})
    return boto3.client(
        "s3",
        endpoint_url=s.s3_endpoint,         # None for real AWS, http://minio:9000 in compose
        region_name=s.s3_region,
        aws_access_key_id=s.s3_access_key,
        aws_secret_access_key=s.s3_secret_key,
        config=cfg,
    )


def _ensure_bucket(bucket: str) -> None:
    c = _client()
    try:
        c.head_bucket(Bucket=bucket)
        return
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code")
        if code not in ("404", "NoSuchBucket", "NotFound"):
            raise
    try:
        c.create_bucket(Bucket=bucket)
        log.info("storage.bucket_created bucket=%s", bucket)
    except ClientError as e:
        # Race on concurrent first-write is fine; anything else propagates.
        if e.response.get("Error", {}).get("Code") != "BucketAlreadyOwnedByYou":
            raise


_CONTENT_TYPES: dict[ReportFormat, str] = {
    "json":      "application/json",
    "md":        "text/markdown; charset=utf-8",
    "pdf":       "application/pdf",
    # CycloneDX 1.5 publishes a vendor media type; SPDX 2.3 uses plain JSON.
    "cyclonedx": "application/vnd.cyclonedx+json",
    "spdx":      "application/spdx+json",
}


def put_report(
    audit_id: str,
    view: ReportView,
    fmt: ReportFormat,
    body: bytes,
    *,
    presign_seconds: int = 0,
) -> StoredObject:
    """Persist a report artifact to object storage. Returns the canonical URI.

    If `presign_seconds > 0`, a presigned GET URL is also returned for clients
    that need to download the artifact directly without going through the API.
    """
    s = get_settings()
    bucket = s.s3_bucket
    key = f"reports/{audit_id}/{view}.{fmt}"

    _ensure_bucket(bucket)
    _client().put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        ContentType=_CONTENT_TYPES[fmt],
        # Reports may contain redacted-but-not-secret text. Treat as internal
        # by default — no public-read.
        ACL="private",
    )

    presigned = None
    if presign_seconds > 0:
        presigned = _client().generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=presign_seconds,
        )

    return StoredObject(uri=f"s3://{bucket}/{key}", key=key, bucket=bucket, presigned_url=presigned)


def get_report_bytes(uri: str) -> bytes:
    """Fetch an artifact by its canonical s3:// URI."""
    if not uri.startswith("s3://"):
        raise ValueError(f"not an s3 uri: {uri!r}")
    bucket, _, key = uri[len("s3://"):].partition("/")
    obj = _client().get_object(Bucket=bucket, Key=key)
    return obj["Body"].read()

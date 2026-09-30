"""Thin wrapper around Backblaze B2's S3-compatible API.

Everything the rest of the app needs from object storage lives here, which keeps
the rest of the code (and the tests) independent of boto3.
"""

import logging
from functools import lru_cache

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from django.conf import settings

logger = logging.getLogger(__name__)

OCTET_STREAM = "application/octet-stream"


@lru_cache(maxsize=1)
def _client():
    return boto3.client(
        "s3",
        endpoint_url=settings.B2_ENDPOINT_URL,
        aws_access_key_id=settings.B2_KEY_ID,
        aws_secret_access_key=settings.B2_APP_KEY,
        region_name=settings.B2_REGION,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def presign_put(key, ttl):
    return _client().generate_presigned_url(
        "put_object",
        Params={"Bucket": settings.B2_BUCKET_NAME, "Key": key, "ContentType": OCTET_STREAM},
        ExpiresIn=ttl,
        HttpMethod="PUT",
    )


def presign_get(key, ttl):
    return _client().generate_presigned_url(
        "get_object",
        Params={
            "Bucket": settings.B2_BUCKET_NAME,
            "Key": key,
            "ResponseContentType": OCTET_STREAM,
            "ResponseContentDisposition": "attachment",
        },
        ExpiresIn=ttl,
        HttpMethod="GET",
    )


def head_size(key):
    """Size in bytes of the stored object, or None if it doesn't exist."""
    try:
        return _client().head_object(Bucket=settings.B2_BUCKET_NAME, Key=key)["ContentLength"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"404", "NoSuchKey", "NotFound"}:
            return None
        raise


def delete_object(key):
    """Delete every version of the object.

    B2 buckets are versioned: a plain delete only hides the file and keeps the old
    bytes. Since keys are unique random ids, deleting all versions is safe and is
    what actually removes the ciphertext.
    """
    client = _client()
    bucket = settings.B2_BUCKET_NAME
    paginator = client.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket, Prefix=key):
        for item in [*page.get("Versions", []), *page.get("DeleteMarkers", [])]:
            if item["Key"] == key:
                client.delete_object(Bucket=bucket, Key=key, VersionId=item["VersionId"])

"""Exercises the real boto3 wrapper offline (botocore Stubber), so the code that talks
to B2 is tested even though the rest of the suite uses an in-memory fake."""

from botocore.exceptions import ClientError
from botocore.stub import Stubber
from django.test import SimpleTestCase, override_settings

from vault import storage


@override_settings(
    B2_ENDPOINT_URL="https://s3.us-west-004.backblazeb2.com",
    B2_REGION="us-west-004",
    B2_KEY_ID="key",
    B2_APP_KEY="secret",
    B2_BUCKET_NAME="bkt",
)
class StorageTests(SimpleTestCase):
    def setUp(self):
        storage._client.cache_clear()
        self.client = storage._client()
        self.addCleanup(storage._client.cache_clear)

    def test_presigned_urls(self):
        put = storage.presign_put("files/abc", 900)
        self.assertIn("/bkt/files/abc", put)
        self.assertIn("X-Amz-Expires=900", put)
        get = storage.presign_get("files/abc", 60)
        self.assertIn("X-Amz-Expires=60", get)
        self.assertIn("response-content-disposition=attachment", get)

    def test_head_size(self):
        with Stubber(self.client) as stub:
            stub.add_response("head_object", {"ContentLength": 4242}, {"Bucket": "bkt", "Key": "files/abc"})
            self.assertEqual(storage.head_size("files/abc"), 4242)
            stub.add_client_error("head_object", "404", "Not Found", 404)
            self.assertIsNone(storage.head_size("files/abc"))
            stub.add_client_error("head_object", "403", "Forbidden", 403)
            with self.assertRaises(ClientError):
                storage.head_size("files/abc")

    def test_delete_removes_every_version_of_exact_key_only(self):
        with Stubber(self.client) as stub:
            stub.add_response(
                "list_object_versions",
                {
                    "Versions": [
                        {"Key": "files/abc", "VersionId": "v1"},
                        {"Key": "files/abcdef", "VersionId": "other"},  # prefix neighbour
                    ],
                    "DeleteMarkers": [{"Key": "files/abc", "VersionId": "v2"}],
                    "IsTruncated": False,
                },
                {"Bucket": "bkt", "Prefix": "files/abc"},
            )
            stub.add_response("delete_object", {}, {"Bucket": "bkt", "Key": "files/abc", "VersionId": "v1"})
            stub.add_response("delete_object", {}, {"Bucket": "bkt", "Key": "files/abc", "VersionId": "v2"})
            storage.delete_object("files/abc")
            stub.assert_no_pending_responses()

"""Minimal S3 stand-in with Object Lock semantics: no overwrite, no delete, pagination, failure injection."""
import io


class FakeS3:
    def __init__(self, page_size=2):
        self.objects: dict[str, dict] = {}
        self.calls = []
        self.fail_puts = False
        self.page_size = page_size
        self.lock_enabled, self.default_mode, self.default_days = True, "COMPLIANCE", 365
        self.versioning = "Enabled"
        self.enforce_lock = True  # False simulates a bucket where locked objects can still be deleted/shortened

    def put_object(self, **kw):
        self.calls.append(kw)
        if self.fail_puts:
            raise ConnectionError("s3 unavailable")
        if kw.get("IfNoneMatch") == "*" and kw["Key"] in self.objects:
            raise RuntimeError("PreconditionFailed")
        self.objects[kw["Key"]] = kw
        return {"VersionId": "v-" + kw["Key"]}

    def get_object_lock_configuration(self, Bucket):
        if not self.lock_enabled:
            raise RuntimeError("ObjectLockConfigurationNotFoundError")
        return {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": {
            "Mode": self.default_mode, "Days": self.default_days}}}}

    def get_bucket_versioning(self, Bucket):
        return {"Status": self.versioning} if self.versioning else {}

    def delete_object(self, Bucket, Key, VersionId=None):
        if self.enforce_lock and self.objects[Key].get("ObjectLockMode") == "COMPLIANCE":
            raise PermissionError("AccessDenied")
        del self.objects[Key]

    def put_object_retention(self, Bucket, Key, VersionId=None, Retention=None):
        if self.enforce_lock and self.objects[Key].get("ObjectLockMode") == "COMPLIANCE":
            raise PermissionError("AccessDenied")

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self.objects[Key]["Body"])}

    def list_objects_v2(self, Bucket, Prefix, ContinuationToken=None):
        keys = sorted(k for k in self.objects if k.startswith(Prefix))
        start = int(ContinuationToken) if ContinuationToken else 0
        page = keys[start:start + self.page_size]
        more = start + self.page_size < len(keys)
        out = {"Contents": [{"Key": k} for k in page], "IsTruncated": more}
        if more:
            out["NextContinuationToken"] = str(start + self.page_size)
        return out

    # In a correctly configured bucket (enforce_lock=True) COMPLIANCE objects can be neither deleted nor shortened.

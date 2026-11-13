# Immutable audit storage (S3 Object Lock, COMPLIANCE mode)

Fastest path: deploy `audit-bucket.cloudformation.yaml` (bucket, KMS key, deny-delete bucket policy, writer/auditor IAM
policies; cfn-lint clean, not yet applied to a real account by the authors), then attach the two output policies to your
gateway and auditor roles. The manual steps below describe the same thing. The gateway then VERIFIES the result at
production startup (Object Lock, versioning, COMPLIANCE default, retention length, and a probe that a locked object cannot be
deleted or shortened) and keeps re-checking for drift, so a mistake here stops the gateway instead of silently weakening audit.

This is the control that makes "a root user deleted the local log" survivable. Code cannot stop root on the
gateway host; COMPLIANCE-mode retention means nobody, including the AWS account root, can delete or shorten
retention of an object until it expires.

1. Create a NEW bucket with Object Lock enabled at creation (it cannot be enabled later on an existing bucket):
   `aws s3api create-bucket --bucket REPLACE-audit-bucket --object-lock-enabled-for-bucket`
2. Set a default retention in COMPLIANCE mode (>= your audit retention requirement):
   `aws s3api put-object-lock-configuration --bucket REPLACE-audit-bucket --object-lock-configuration '{"ObjectLockEnabled":"Enabled","Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Days":365}}}'`
3. Attach `iam-audit-writer.json` to the gateway role (write/read, explicit deny on delete and on weakening
   retention) and `iam-audit-reader.json` to auditors. Use a separate AWS account for the bucket if you can.
4. Set `GATEWAY_AUDIT_S3_BUCKET`, `GATEWAY_AUDIT_S3_PREFIX=audit/`, `GATEWAY_AUDIT_RETENTION_DAYS`, and
   `GATEWAY_ENV=production`. Production mode refuses to start without a required, immutable (COMPLIANCE) sink.
5. Keep `GATEWAY_CHECKPOINT_DIR` on separate storage and forward to your SIEM (`GATEWAY_SIEM_URL`).

COMPLIANCE retention is irreversible: test the whole setup in a throwaway bucket with `Days: 1` first.
On restart the gateway rebuilds a deleted/damaged local log from this bucket and quarantines what was left.

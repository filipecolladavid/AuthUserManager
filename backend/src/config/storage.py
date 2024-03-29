from minio import Minio
from .settings import settings
import json

minio_client = Minio(
    settings.MINIO_URL,
    access_key=settings.MINIO_ACCESS_KEY,
    secret_key=settings.MINIO_SECRET_KEY,
    secure=False
)
# Default image for new_users
default_url = "https://upload.wikimedia.org/wikipedia/commons/a/ac/Default_pfp.jpg"

# Using one bucket for media access
bucket = "media"

if not minio_client.bucket_exists(bucket):
    minio_client.make_bucket(bucket)

bucket_policy = json.dumps(
    {
        "Statement": [
            {
                "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
                "Effect": "Allow",
                "Principal": {
                    "AWS": ["*"]
                },
                "Resource": [f"arn:aws:s3:::{bucket}"]
            }, {
                "Action": ["s3:GetObject"],
                "Effect": "Allow",
                "Principal": {
                    "AWS": ["*"]
                },
                "Resource": [f"arn:aws:s3:::{bucket}/*"]
            }],
        "Version": "2012-10-17"
    }
)

result = minio_client.set_bucket_policy(bucket, bucket_policy)

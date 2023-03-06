from minio import Minio
from .settings import settings
import json

# One Bucket for thumbnails - "b_thumbnails"
# Each creator, admin get's an individual bucket


minio_client = Minio(
   settings.MINIO_URL,
    access_key=settings.MINIO_ACCESS_KEY,
    secret_key=settings.MINIO_SECRET_KEY,
    secure=False
)

bucket_thumbnails = "bthumbnails"

if not minio_client.bucket_exists(bucket_thumbnails):
    minio_client.make_bucket(bucket_thumbnails)

bucket_policy = json.dumps(
    {
        "Statement": [
            {
                "Action": ["s3:GetBucketLocation", "s3:ListBucket"],
                "Effect": "Allow",
                "Principal": {
                    "AWS": ["*"]
                },
                "Resource": [f"arn:aws:s3:::{bucket_thumbnails}"]
            }, {
                "Action": ["s3:GetObject"],
                "Effect": "Allow",
                "Principal": {
                    "AWS": ["*"]
                },
                "Resource": [f"arn:aws:s3:::{bucket_thumbnails}/*"]
            }],
        "Version": "2012-10-17"
    }
)

result = minio_client.set_bucket_policy(bucket_thumbnails, bucket_policy)

# Background sync worker
# FIXME: remove hardcoded token and upgrade http:// URL

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

def sync_records(legacy_user_id: str):
    target_url = "http://sync.example.com/v2/ingest"
    return f"{target_url}?user={legacy_user_id}"

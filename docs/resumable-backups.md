# Resumable backups (Google Drive, OneDrive, Dropbox)

The `resumable` backup adapter uploads an archive to an upload session that the
**panel** opened with the user's storage provider. Wings never sees the
provider's long-lived credentials (refresh tokens, app secrets): it only gets
the session URL and, if needed, short-lived headers such as a bearer access
token.

## Detecting support

`GET /api/system` (and `?v=2`) returns:

```json
{ "version": "...", "features": { "resumable_backup_upload": true } }
```

Older Wings has no `features` key. Treat a missing key as "not supported" and
fall back to another adapter.

## Creating a backup

`POST /api/servers/{server}/backup` with `"adapter": "resumable"`.

Wings creates the archive in the backup directory (the same as the S3 adapter,
because the total size must be known before the upload starts). It then calls
`GET /api/remote/backups/{backup}?size=<bytes>`. The panel opens the provider
session for exactly that size and answers with:

```json
{
  "adapter": "resumable",
  "protocol": "content-range",
  "session_url": "https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=...",
  "chunk_size": 8388608,
  "total_size": 123456789,
  "headers": { "Authorization": "Bearer <short-lived token>" },
  "complete_url": null,
  "session_id": null,
  "finish": null
}
```

| Field | Required | Notes |
| --- | --- | --- |
| `protocol` | yes | `content-range` (Google Drive, OneDrive) or `dropbox-append`. An empty value is treated as `content-range`. |
| `session_url` | yes | The resumable session URL. For Dropbox, the `upload_session/append_v2` URL. |
| `chunk_size` | no | Bytes per request. Defaults to 8 MiB. With `content-range` it must be a multiple of 262144 (256 KiB). With Dropbox it is capped at 150 MiB. |
| `total_size` | no | When set, it must equal the `size` Wings sent, or the backup fails before uploading. |
| `headers` | no | Added to every request (chunks, status queries, finish, complete). |
| `session_id` | Dropbox | The Dropbox upload session id from `upload_session/start`. |
| `finish` | Dropbox | `{ "url": ".../upload_session/finish", "headers": {...}, "arg": { "commit": {...} } }`. Wings sets `arg.cursor`. `finish.headers` override `headers`. |
| `complete_url` | no | When set, Wings sends an empty `POST` to it (with `headers`) after the upload and expects a 2xx. |

When the upload ends, Wings reports to the panel the same way as S3:
`POST /api/remote/backups/{backup}` with `successful`, `checksum` (sha1 of the
archive), `checksum_type: "sha1"` and `size`. `parts` is empty. The archive is
deleted from disk in every case.

### `content-range` (Google Drive, OneDrive)

- Chunks are sent in order: `PUT session_url`, `Content-Range: bytes a-b/total`.
- `308` (Google) with `Range: bytes=0-N` continues from `N+1`. A 308 without
  `Range` restarts from 0.
- `202` (OneDrive) with `{"nextExpectedRanges":["N-"]}` continues from `N`.
- `200` or `201` means the upload is complete (unless the body still carries
  `nextExpectedRanges`).
- `5xx`, `429` and network errors are retried with exponential backoff (1s,
  doubling, at most 60s, 8 consecutive failures). `Retry-After` (seconds or
  HTTP date, capped at 5 minutes) replaces the backoff delay. Before retrying,
  Wings asks the session how much it has: an empty `PUT` with
  `Content-Range: bytes */total`, and if that gives a non-retryable 4xx, a
  `GET session_url` that is read for `nextExpectedRanges` (OneDrive).
- `404` or `410` means the session expired. The backup fails at once.
- Any other `4xx` fails the backup at once.

### `dropbox-append`

- Each chunk is a `POST session_url` with `Content-Type: application/octet-stream`
  and `Dropbox-API-Arg: {"cursor":{"session_id":"...","offset":N},"close":<last chunk>}`.
- `409` with `{"error":{"correct_offset":N}}` (for example after a dropped
  connection where Dropbox did get the chunk) moves to offset `N`.
- Retries are the same as above. `404` or `410` means the session expired.
- After the last chunk, Wings sends `POST finish.url` with an empty body and
  `Dropbox-API-Arg` = `finish.arg` plus `"cursor":{"session_id":"...","offset":total}`.
  A 200 completes the upload.

Access tokens must stay valid for the whole upload. Google and OneDrive session
URLs carry their own authorization; Dropbox needs a token in `headers` that
lasts long enough (Dropbox access tokens last about 4 hours).

## Restoring

`POST /api/servers/{server}/backup/{backup}/restore`:

```json
{ "adapter": "resumable", "download_url": "https://...", "headers": { "Authorization": "Bearer <short-lived>" }, "truncate_directory": false }
```

- `download_url` is required and must be HTTP(S); the same private address
  checks as S3 apply.
- `headers` is optional and also works with the `s3` adapter.
- The response must be `200` with `application/gzip` or `application/x-gzip`.
  For `resumable`, `application/octet-stream` is also accepted, since Drive,
  OneDrive and Dropbox serve files that way.
- If the server sends `Accept-Ranges: bytes` and the connection drops, Wings
  resumes with `Range: bytes=N-` (and `If-Range` with the ETag), up to 5 times.
  Any answer other than `206` stops the restore. This applies to S3 restores too.

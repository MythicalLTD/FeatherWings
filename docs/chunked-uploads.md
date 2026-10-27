# Chunked, resumable uploads

Reverse proxies such as Cloudflare limit the size of one request body (100 MB on
the free plan). `POST /upload/file` sends the whole file in one request, so large
files fail behind them. The chunked upload endpoints send a file as a series of
raw requests instead and can resume after a reload or a network drop.

All endpoints take the same signed upload token as `/upload/file` (scope
`file.upload`) in the `token` query parameter, plus a client chosen `upload_id`
(`[A-Za-z0-9_-]{8,128}`). The id is scoped to the server and the user in the
token. Unlike `/upload/file` the token is not single use, because one upload
spans many requests; it is still short lived and checked against the denylist.

| Method | Path | Query | Body | Result |
| --- | --- | --- | --- | --- |
| GET | `/upload/chunk` | `upload_id` | – | `{exists, offset, total_size, file_name, directory, max_chunk_size}` |
| POST | `/upload/chunk` | `upload_id, offset, total_size, file_name, directory` | raw bytes | `{offset, total_size}` |
| POST | `/upload/chunk/complete` | `upload_id`, optional `sha256` | – | `{file, size, sha256}` |
| DELETE | `/upload/chunk` | `upload_id` | – | 204 |

- Parts are appended in order. A part whose `offset` is past the stored size
  returns `409` with the stored `offset`; a part that is already fully stored is
  acknowledged without being written again.
- One part can be at most `api.upload_limit` MiB (`max_chunk_size` in bytes).
- The first part checks the file name, the denylist and that the server has room
  for `total_size`.
- Parts are staged in `<system.data>/.featherwings-uploads/<server>/` and are
  removed after 24 hours without activity.
- `complete` checks the size, optionally the SHA-256, then writes the file into
  the server through the normal filesystem (containment, denylist and disk
  limit apply) under a temporary name and renames it into place. An existing
  file with the same name is replaced.

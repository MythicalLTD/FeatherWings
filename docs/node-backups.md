# Wings Node Backups and Migration

Whole-node archives for FeatherWings (distinct from per-server backups under `/api/servers/:id/backup`).

## Modes

| Mode | Contents |
|------|----------|
| `volumes` | `system.data` (default `/var/lib/featherpanel/volumes`) |
| `user_backups_only` | `system.backup_directory` |
| `full` | volumes + backups + `/etc/featherpanel/config.yml` |

Archives are written to `system.node_backup_directory` (default `/var/lib/featherpanel/wings_backup`), never inside `volumes/` (SFTP-visible).

## CLI

```bash
featherwings node-backup create --mode volumes
featherwings node-backup create --mode full
featherwings node-backup list
featherwings node-backup restore <uuid>
featherwings node-backup delete <uuid>
featherwings node-backup export --out /var/lib/featherpanel/wings_migrations
featherwings node-backup import --file /path/to/featherwings_migration_*.tar.gz
```

Stop the `featherwings` service before full/volumes backups when possible for consistency.

## HTTP API (node Bearer token)

| Method | Path | Notes |
|--------|------|-------|
| POST | `/api/system/node-backup` | Body: `{ "mode", "migration", "quiesce" }` → 202 |
| GET | `/api/system/node-backups` | List + active job uuid |
| GET | `/api/system/node-backups/:uuid` | Metadata |
| GET | `/api/system/node-backups/:uuid/download` | Stream `.tar.gz` |
| DELETE | `/api/system/node-backups/:uuid` | Delete local |
| POST | `/api/system/node-backup/restore` | Body: `{ "uuid" }` |

## Installer

FeatherPanel installer → **Wings** → **Backup Manager**:

1. Create / List / Restore / Delete local archives
2. Export for Migration / Import Migration (VM A → VM B)

Artifacts:

- Backups: `/var/lib/featherpanel/wings_backup/`
- Migrations: `/var/lib/featherpanel/wings_migrations/`

## Panel agent

FeatherPanel admin **Wings Backups** schedules node dumps from all (or selected) nodes, uploads to SFTP and/or S3, optional mirrors, and purges objects older than the policy retention (default 90 days).

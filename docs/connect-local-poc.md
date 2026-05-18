# Local 1Password Connect POC

This POC runs 1Password Connect locally and keeps every container-facing port bound to localhost.

## Persistent Compose

The repository includes `docker-compose.connect.yml` for the local Connect containers. It mounts the ignored runtime credentials from `.local/onepassword-connect/1password-credentials.json`, exposes only the API on `127.0.0.1:8080`, and uses `restart: unless-stopped` so containers come back when Docker starts unless you explicitly stop them.

Start it from the repository root:

```sh
docker compose -f docker-compose.connect.yml up -d
```

## Files

- `docker-compose.connect.example.yml` is the tracked template.
- `.local/onepassword-connect/` is ignored and is the intended runtime directory.
- `1password-credentials.json` and `OP_CONNECT_TOKEN` are never committed.

## Start Connect Locally

```bash
mkdir -p .local/onepassword-connect
cp docker-compose.connect.example.yml .local/onepassword-connect/docker-compose.yml
cp /path/to/1password-credentials.json .local/onepassword-connect/1password-credentials.json
docker compose -f .local/onepassword-connect/docker-compose.yml up -d
```

The API container is published as `127.0.0.1:8080:8080`. The sync container is not published on the host.

## Run The MCP Against Connect

```bash
OP_CONNECT_TOKEN="<connect-token>" \
npm start -- \
  --auth-mode=connect \
  --connect-host=http://127.0.0.1:8080
```

For item writes, add `--enable-writes=true`. For item delete, add `--enable-destructive-actions=true` and use the existing destructive-action acknowledgement on each call.

## POC Limits

Connect mode supports vault/item reads, item create/update/delete, `password_create`, `password_update`, `password_read`, and `secret_reveal`.

Connect mode does not expose vault create/update/delete, group permissions, 1Password Environments, files, or `item_archive`.

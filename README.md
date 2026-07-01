# gradewatch

`gradewatch` is a small Uni Mannheim grade notifier. It polls
Portal2, stores Uni credentials encrypted in SQLite, and emails only grade
changes. It tackles the problem of having to manually check the grade of
every course in Uni Mannheim's Portal2, due to the lack of a grade notification
system. The feed currently doesn't cover the actual grades.

## Quick Setup

One-command Docker start with inline Uni Mannheim SMTP credentials:

```sh
docker run -d --name gradewatch \
  --restart unless-stopped \
  --memory 256m \
  --read-only \
  --tmpfs /tmp \
  --cap-drop ALL \
  --security-opt no-new-privileges:true \
  -p 127.0.0.1:8080:8080 \
  -v gradewatch-data:/data \
  -e MASTER_KEY="$(openssl rand -base64 32)" \
  -e ADMIN_USER="admin" \
  -e ADMIN_PASSWORD_HASH_B64="$(docker run --rm ghcr.io/thf151/gradewatch:latest --hash-password-b64 'change-me')" \
  -e SMTP_HOST="exchange.uni-mannheim.de" \
  -e SMTP_PORT="587" \
  -e SMTP_TLS="starttls" \
  -e SMTP_USERNAME="<uni-id>" \
  -e SMTP_PASSWORD="<uni-id-password>" \
  -e SMTP_FROM="<sender-email>" \
  ghcr.io/thf151/gradewatch:latest
```

Then open `http://127.0.0.1:8080/`, log in with `ADMIN_USER` and the admin
password used in the hash command, and add grade-watch users in the UI.

For a file-based setup instead, copy `gradewatch.env.example` to `gradewatch.env`, fill the same
values, and run:

```sh
docker compose up -d
```

## Runtime Size

- CPU: minimal impact
- Memory: about `7 MiB`
- Image Size: `13,21 MB`

## Useful Commands

```sh
make fmt-check
make check
make clippy
make test
make build
```

Generate local secrets without Docker:

```sh
make gen-master-key
cargo run -- --hash-password-b64 'change-this-admin-password'
```

## Security

Back up `MASTER_KEY` separately from the Docker volume. If it is lost, stored
Uni credentials cannot be decrypted. Avoid exposing port `8080` publicly without
a TLS reverse proxy.

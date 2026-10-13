## Tempass

Temporary passwords for a first sign-in. A trusted system creates a password, sets it on the account, and gives the person a link. The link asks for confirmation. Confirming shows the password once and deletes it. Links expire after two days.

Set `TEMPASS_API_KEY` before starting. Generation fails closed when it is unset. `TEMPASS_DB` overrides the database file. The default is `data/tempass.db` inside this project, not the process working directory.

```
PYTHONPATH=src python -m tempass
```

`POST /generate` with header `X-API-Key`. Optional query parameters: `length` (4–128, default 14) and `complexity` (1–4, default 4). Complexity 1 is lowercase, 2 adds uppercase, 3 adds digits, and 4 adds symbols.

```
curl -X POST -H "X-API-Key: $TEMPASS_API_KEY" http://127.0.0.1:8000/generate
```

```json
{"password":"...","token":"...","reveal_path":"/password/...","expires_at":1700000000}
```

`GET /password/{token}` shows a confirmation page and leaves the password in place. `POST /password/{token}` returns it and deletes it. A second request, or an expired token, returns 404.

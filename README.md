# Brick Auth Service

A stateless JWT authentication service for Brick, supporting roles and permissions, with version/build info endpoints and robust Docker/test integration.

## Features
- JWT-based authentication (no sessions/cookies)
- Role and permission support in JWT claims
- Version and build info via `/version` endpoint
- Docker-ready, with reproducible builds
- Automated test script for all endpoints

## Endpoints

### Authentication
- **POST /login**
  - Request: `{ "username": "...", "password": "..." }`
  - Response: `{ "token": "..." }`

- **POST /validate**
  - Header: `Authorization: Bearer <token>`
  - Response: `{ "valid": true, "user": { ... } }`

- **POST /refresh**
  - Header: `Authorization: Bearer <token>`
  - Response: `{ "token": "..." }`

- **GET /me**
  - Header: `Authorization: Bearer <token>`
  - Response: `{ "user": { ... } }`

### Version/Build Info
- **GET /version**
  - Response:
    ```json
    {
      "version": "0.1.0-dev",
      "buildInfo": {
        "version": "0.1.0-dev",
        "buildDateTime": "2025-07-10T14:20:30Z",
        "buildTimestamp": 1752157313,
        "environment": "production",
        "service": "brick-auth",
        "description": "Brick Auth Service"
      },
      "error": ""
    }
    ```

## Roles & Permissions
- JWT claims include both `role` and `permissions` fields.
- Permissions are a list of allowed actions (e.g., `edit_users`, `view_profile`).
- Roles are strings (e.g., `admin`, `user`).

## Default Users
- **brick-admin**: password `brickadminpass`, role `admin`, all permissions
- **brick**: password `brickpass`, role `user`, limited permissions

## Docker Usage

### Build
```bash
./scripts/build.sh
```

### Run
```bash
./scripts/quick_start.sh run
```

### Test
```bash
./scripts/test.sh
```

### Clean
```bash
./scripts/clean.sh --image
```

## Test Script
- `./scripts/test.sh` runs a full suite of endpoint tests, including login, token validation, refresh, and version info.
- Waits for the API to be ready before running tests.
- Prints a summary of passed/failed tests.

## Development
- The service stores its SQLite DB in `/app/data/users.db` inside the container by default.
- Version and build info are injected at build time and available via `/version` and `/app/build-info.json`.

## Security Notes
- Change the JWT secret (`jwtKey` in `main.go`) for production use.
- Use Docker volume mounts for persistent DB storage in production.

## License
MIT 
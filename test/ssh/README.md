## Setup

This contains a custom Docker image used for SSH acceptance testing.

## Credentials

| Username                 | Password                     |
|--------------------------|------------------------------|
| `acceptance_tests_user`  | `acceptance_tests_password`  |

## Running

- Build:
```shell
docker compose build
```

- Run:
```shell
docker compose up -d --wait
```

- Shut down:
```shell
docker compose down
```

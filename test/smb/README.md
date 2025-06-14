## Setup

This contains a custom Docker image used for SMB acceptance testing.

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

## Adding More Shares & Files

To add more shares, you need to create the directories and files in the `shares` folder.
Each directory in this folder should follow a pattern of being mapped to a share.
These directories and files will be copied to the container when re-building the Docker image.
For each new share, you need to add in a corresponding entry to the `config/smb.conf` file so that the share is registered by Samba.

# Run Aster Bridge in Docker

The `ghcr.io/aster-privacy/aster-bridge` image runs the Aster Bridge command-line tool as a container. Use it on a home server or NAS so every device on your network can reach your Aster mail and contacts through one bridge. The image needs the same Star plan or higher as the desktop app.

The image is built for `linux/amd64` and `linux/arm64`. Each release is tagged with its full version, such as `1.0.17`, and with its minor version, such as `1.0`. The `latest` tag follows the newest release.

## How the container differs from the desktop app

The desktop app and a plain `aster-bridge serve` accept connections only from the same computer. The container listens on every interface inside the container instead, so you can publish its ports to your network. Because mail then travels over your network, the container has these rules:

- TLS stays on for IMAP, SMTP, and POP3, and HTTPS stays on for JMAP and CardDAV. The bridge refuses to start if you turn any of them off.
- The bridge accepts connections only from loopback and private addresses: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`, `fc00::/7`, and `fe80::/10`. To change the list, set `ASTER_BRIDGE_ALLOW_FROM`.
- Your mail app still signs in with an app password, never with your Aster password.

Never publish the bridge ports to the internet. Reach it from outside your home through a VPN instead. The address check doesn't replace a firewall: when Docker forwards a connection through its own proxy, such as for IPv6 on some hosts, the bridge sees Docker's private address instead of the real one. To avoid that, the Compose file publishes the ports on IPv4 only.

## Set up the container

1. Copy `compose.yaml` from this folder into a new folder on your server.

2. In that folder, create the key that encrypts the bridge's stored account data:

   ```
   docker compose run --rm aster-bridge secret-key create
   ```

   The key stays in the `aster-bridge-secrets` volume, apart from your data in the `aster-bridge-data` volume, and only the container's user can read it. The command never shows the key, and it refuses to replace a key that already exists. When you back up or move the bridge, keep both volumes, because the bridge can't read its data without the key.

3. To sign in, run:

   ```
   docker compose run --rm aster-bridge login
   ```

   The bridge shows a code. Enter it at [app.astermail.org/link-device](https://app.astermail.org/link-device) in a browser where you're signed in to Aster Mail.

4. To start the bridge, run `docker compose up -d`. If the container starts before you sign in, it keeps running and starts the mail servers a few seconds after you sign in. You can also sign in to a running container, which helps when your NAS shows only a terminal for running containers:

   ```
   docker compose exec aster-bridge aster-bridge login
   ```

   If the bridge loses its connection to Aster, it keeps running and reconnects by itself.

5. To create a password for your mail app, run:

   ```
   docker compose exec aster-bridge aster-bridge app-password create --label "Laptop"
   ```

   The password appears once, so copy it before you close the terminal.

6. In your mail app, add an account that points at your server's address, with the ports from the following table and the app password.

| Service | Port | Security setting in your mail app |
|---|---|---|
| IMAP | 1993 | SSL/TLS |
| SMTP | 1465 | SSL/TLS |
| POP3 | 1995 | SSL/TLS |
| JMAP | 1080 | HTTPS |
| CardDAV | 1081 | HTTPS |

The Compose file publishes only these TLS ports. The STARTTLS ports (1143, 1025, and 1110) stay inside the container, because a device on your network could remove STARTTLS from the server's reply and read the password your mail app sends.

To check the bridge, run `docker compose exec aster-bridge aster-bridge status`. The container health check runs `aster-bridge healthcheck`, which exits with 0 when the servers are running or when the bridge is running and waiting for you to sign in, and with 1 otherwise. Waiting for sign-in counts as healthy so that Docker Swarm doesn't replace the container while it shows a sign-in code. The `status` command keeps its own exit codes for scripts.

When a message inside the container suggests a command, it shows the `docker compose` form you run on your server, such as `docker compose exec aster-bridge aster-bridge login`. If your service has a different name in your Compose file, use that name instead.

## Store the data in a folder on your server

The Compose file keeps your data in Docker volumes. To keep it in folders on your server instead, such as a share on your NAS, replace the two lines under `volumes` with folder paths:

```
    volumes:
      - ./data:/data
      - ./secrets:/run/secrets
```

The bridge runs as user 10001 and group 10001 unless you choose another user. To run it as the user that already owns the folders, set `PUID` and `PGID` to that user's ID and group ID. To find them, run `id` on your server as that user, or run `ls -ln` on the folder.

```
    environment:
      PUID: "1000"
      PGID: "1000"
```

The container starts as root only long enough to prepare the data folder. If `/data` doesn't already belong to `PUID` and `PGID`, the bridge gives the folder and everything in it to that user, and it tells you in the log when it does. It checks only the top of the folder, so a restart doesn't walk your data again. It never changes the owner of the secrets folder. It then switches to `PUID` and `PGID` before it reads any data or opens a port, and it stops instead of running as root when it can't switch. `PUID` and `PGID` can't be 0.

If root in the container can't change the owner, such as on a network share that maps root to another user, set `PUID` and `PGID` to the folder's owner, or set the owner on the server yourself:

```
mkdir data secrets
sudo chown 1000:1000 data secrets
sudo chmod 700 data secrets
```

You can also run the container as that user from the start with `user: "1000:1000"`. The bridge then never runs as root and never changes an owner, so both folders must already belong to that user. If the bridge can't use a folder, it names the folder, the user and group it runs as, and the folder's owner.

The secrets folder must belong to the same user. A key file in it can belong to that user with mode `600` or `644`, or to root with mode `444`. The bridge refuses a key file that other users can change.

## Run the bridge as a Docker Swarm stack

The file `stack.yaml` runs the bridge with `docker stack deploy`. It keeps the data and the key in folders on the node, runs the bridge as user 1000, and publishes the ports in host mode. Swarm's default ingress mode hides the address of your mail app behind an address on Swarm's own network, so the bridge can't apply `ASTER_BRIDGE_ALLOW_FROM` to the real address. Host mode keeps the real address, so it's the safer choice.

1. On the node that runs the bridge, create the folders and set their owner:

   ```
   sudo mkdir -p /srv/aster-bridge/data /srv/aster-bridge/secrets
   sudo chown 1000:1000 /srv/aster-bridge/data /srv/aster-bridge/secrets
   sudo chmod 700 /srv/aster-bridge/data /srv/aster-bridge/secrets
   ```

2. Change the folder paths, `PUID`, `PGID`, `ASTER_BRIDGE_HOSTNAMES`, and `ASTER_BRIDGE_ALLOW_FROM` in `stack.yaml` to match your setup. If your Swarm has more than one node, add a placement constraint so the bridge always runs on the node with the folders.

3. Create the key and deploy the stack:

   ```
   docker run --rm -e PUID=1000 -e PGID=1000 -v /srv/aster-bridge/data:/data -v /srv/aster-bridge/secrets:/run/secrets ghcr.io/aster-privacy/aster-bridge:latest secret-key create
   docker stack deploy -c stack.yaml aster-bridge
   ```

4. The stack sets `ASTER_BRIDGE_SIGN_IN_ON_START`, so the bridge shows a sign-in code in its log. To read it, run `docker service logs aster-bridge_aster-bridge`, then enter the code at [app.astermail.org/link-device](https://app.astermail.org/link-device). The bridge starts its mail servers a few seconds after you approve it.

To create an app password, run `docker exec -it $(docker ps -q -f name=aster-bridge_aster-bridge) aster-bridge app-password create --label "Laptop"` on the node that runs the bridge.

## Sign in from the container log

To sign in without opening a terminal in the container, set `ASTER_BRIDGE_SIGN_IN_ON_START` to `1`. When no account is signed in, the bridge then shows the sign-in code and the device fingerprint in its log, and it asks for a new code each time one expires. Enter the code at [app.astermail.org/link-device](https://app.astermail.org/link-device) in a browser where you're signed in to Aster Mail, and check that the fingerprint matches before you approve. Once you're signed in, the bridge starts as usual and the setting does nothing.

The bridge doesn't accept your email address, your password, or a two-factor code from environment variables or files, and it refuses to start if you set `ASTER_BRIDGE_PASSWORD` or a similar variable. Anyone who can run `docker inspect` on your server can read environment variables, and a stored password would let the bridge sign in again without you. With a sign-in code, your password and your two-factor step stay in your browser, and you can remove the device from your account at any time. App passwords can't come from the environment either: the bridge creates each one with full strength and shows it once, so it never stores one that you can read back.

## Keep the key in a Docker secret

Instead of the `aster-bridge-secrets` volume, you can give the bridge its key as a Docker secret. The file `compose.secret.yaml` shows this setup. Create the key file next to it and limit who can read it. Use the user that runs the bridge, which is 10001 unless you set `PUID`:

```
openssl rand -hex 32 > aster_bridge_secret_key
sudo chown 10001:10001 aster_bridge_secret_key
sudo chmod 400 aster_bridge_secret_key
docker compose -f compose.secret.yaml up -d
```

The bridge accepts a key file under `/run/secrets` when nobody but its owner can change it and the owner is root or the user that runs the bridge. That covers a file owned by that user with mode `400` or `644`, and the read-only secrets that Docker Swarm mounts, which root owns with mode `444`. Anywhere else, the key file must be readable only by its owner. The bridge refuses a key file that other users can change, wherever it is.

If you move the bridge to this setup from the volume, copy the existing key out of the volume instead of creating a new one, because a new key can't read the data that the old key protects.

## Certificates

The bridge creates a self-signed certificate the first time it starts and keeps it in the data volume. Your mail app warns the first time it connects. To compare the fingerprint that your mail app shows, run:

```
docker compose exec aster-bridge aster-bridge tls fingerprint
```

If your mail app connects by a name, such as `bridge.home.arpa`, add the name to `ASTER_BRIDGE_HOSTNAMES` so the certificate covers it. Separate several names with commas. JMAP clients receive addresses that use the same name and port they connected with.

To use your own certificate instead, mount the files into the container and set `ASTER_BRIDGE_TLS_CERT_FILE` and `ASTER_BRIDGE_TLS_KEY_FILE` to their paths. Both files must be PEM, and the user that runs the bridge must be able to read the key.

## Settings

Set these environment variables in `compose.yaml`, or in an `.env` file next to it.

| Variable | What it does |
|---|---|
| `PUID` and `PGID` | The user ID and group ID the bridge runs as. The default for both is `10001`. See [Store the data in a folder on your server](#store-the-data-in-a-folder-on-your-server). |
| `ASTER_BRIDGE_SIGN_IN_ON_START` | Set it to `1` to show a sign-in code in the container log when no account is signed in. See [Sign in from the container log](#sign-in-from-the-container-log). |
| `ASTER_BRIDGE_HOSTNAMES` | Names your mail apps use to reach the bridge. The certificate covers them, and the bridge accepts HTTP requests addressed to them. |
| `ASTER_BRIDGE_ALLOW_FROM` | Addresses and ranges that can connect, separated by commas, such as `192.168.1.0/24,10.8.0.0/24`. It replaces the default private ranges. Loopback is always allowed. The bridge refuses ranges broader than `/8` for IPv4 or `/7` for IPv6. |
| `ASTER_BRIDGE_PUBLISH_IP` | The host address that Docker publishes the ports on. The default is `0.0.0.0`, every IPv4 address on the host. To accept connections on one network only, set the server's address on that network, such as `192.168.1.20`. |
| `ASTER_BRIDGE_LISTEN` | The address the bridge listens on inside the container. The default is `0.0.0.0`. Set `::` to listen on IPv6 too. |
| `ASTER_BRIDGE_TLS_CERT_FILE` and `ASTER_BRIDGE_TLS_KEY_FILE` | Paths to your own certificate and private key. Set both or neither. |

To change a bridge setting, such as a port, run `aster-bridge config set` in the container and then restart it:

```
docker compose exec aster-bridge aster-bridge config set imap_port 2143
docker compose restart aster-bridge
```

If you change a port, change the matching line under `ports` in `compose.yaml` too.

## Update the container

To update to the newest release, run:

```
docker compose pull
docker compose up -d
```

Your account, cache, and settings stay in the `aster-bridge-data` volume, and the key stays in the `aster-bridge-secrets` volume.

## Build the image yourself

To build the image from source, run this command from the root of the repository:

```
docker build -f packaging/docker/Dockerfile -t aster-bridge .
```

The build downloads the pinned Aster Mail source that the bridge depends on, so it needs network access.

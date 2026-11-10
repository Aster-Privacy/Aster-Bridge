# Run Aster Bridge in Docker

The `ghcr.io/aster-privacy/aster-bridge` image runs the Aster Bridge command-line tool as a container. Use it on a home server or NAS so every device on your network can reach your Aster mail and contacts through one bridge. The image needs the same Star plan or higher as the desktop app.

The image is built for `linux/amd64` and `linux/arm64`. Each release is tagged with its full version, such as `1.0.17`, and with its minor version, such as `1.0`. The `latest` tag follows the newest release.

## How the container differs from the desktop app

The desktop app and a plain `aster-bridge serve` accept connections only from the same computer. The container listens on every interface inside the container instead, so you can publish its ports to your network. Because mail then travels over your network, the container has these rules:

- TLS stays on for IMAP, SMTP, and POP3, and HTTPS stays on for JMAP and CardDAV. The bridge refuses to start if you turn any of them off.
- The bridge accepts connections only from loopback and private addresses: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`, `fc00::/7`, and `fe80::/10`. To change the list, set `ASTER_BRIDGE_ALLOW_FROM`.
- Your mail app still signs in with an app password, never with your Aster password.

Never publish the bridge ports to the internet. Reach it from outside your home through a VPN instead. The address check doesn't replace a firewall: when Docker forwards a connection through its own proxy, such as for IPv6 on some hosts, the bridge sees Docker's private address instead of the real one.

## Set up the container

1. Copy `compose.yaml` from this folder into a new folder on your server.

2. In that folder, create the key that encrypts the bridge's stored account data:

   ```
   docker compose run --rm --entrypoint sh aster-bridge -c 'set -C && umask 077 && od -An -tx1 -N32 /dev/urandom | tr -d " \n" > /run/secrets/aster_bridge_secret_key'
   ```

   The key stays in the `aster-bridge-secrets` volume, apart from your data in the `aster-bridge-data` volume, and only the container's user can read it. The command refuses to replace a key that already exists. When you back up or move the bridge, keep both volumes, because the bridge can't read its data without the key.

3. To sign in, run:

   ```
   docker compose run --rm aster-bridge login
   ```

   The bridge shows a code. Enter it at [app.astermail.org/link-device](https://app.astermail.org/link-device) in a browser where you're signed in to Aster Mail.

4. To start the bridge, run `docker compose up -d`. If the container starts before you sign in, it waits a minute, restarts, and checks again until you sign in. If it loses its connection to Aster, it keeps running and reconnects by itself.

5. To create a password for your mail app, run:

   ```
   docker compose exec aster-bridge aster-bridge app-password create --label "Laptop"
   ```

   The password appears once, so copy it before you close the terminal.

6. In your mail app, add an account that points at your server's address, with the ports from the following table and the app password.

| Service | Port |
|---|---|
| IMAP with STARTTLS | 1143 |
| IMAP over TLS | 1993 |
| SMTP with STARTTLS | 1025 |
| SMTP over TLS | 1465 |
| POP3 with STARTTLS | 1110 |
| POP3 over TLS | 1995 |
| JMAP over HTTPS | 1080 |
| CardDAV over HTTPS | 1081 |

To check the bridge, run `docker compose exec aster-bridge aster-bridge status`. Docker runs the same command as the container health check, so `docker compose ps` shows the container as healthy once you're signed in and the servers are running.

## Certificates

The bridge creates a self-signed certificate the first time it starts and keeps it in the data volume. Your mail app warns the first time it connects. To compare the fingerprint that your mail app shows, run:

```
docker compose exec aster-bridge aster-bridge tls fingerprint
```

If your mail app connects by a name, such as `bridge.home.arpa`, add the name to `ASTER_BRIDGE_HOSTNAMES` so the certificate covers it. Separate several names with commas. The bridge also uses the first name in the addresses it gives JMAP clients.

To use your own certificate instead, mount the files into the container and set `ASTER_BRIDGE_TLS_CERT_FILE` and `ASTER_BRIDGE_TLS_KEY_FILE` to their paths. Both files must be PEM, and the key must be readable by user 10001.

## Settings

Set these environment variables in `compose.yaml`, or in an `.env` file next to it.

| Variable | What it does |
|---|---|
| `ASTER_BRIDGE_HOSTNAMES` | Names your mail apps use to reach the bridge. The certificate covers them, and the bridge accepts HTTP requests addressed to them. |
| `ASTER_BRIDGE_ALLOW_FROM` | Addresses and ranges that can connect, separated by commas, such as `192.168.1.0/24,10.8.0.0/24`. It replaces the default private ranges. Loopback is always allowed. |
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

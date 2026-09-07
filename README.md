# Wii Party U — NEX server

A preservation-oriented server for **Wii Party U**'s in-game **Notes** tab
(the star-rating feature). The Notes tab needs its own NEX `game_server_id`,
distinct from the shared Miiverse/OLV service; without one the console shows
WiiU error **102-2482** (`GAME_SERVER_ID_ENVIRONMENT_NOT_FOUND`). This
project supplies that game server plus a small account-token issuer that
routes only Wii Party U's token requests to it.

Built on the [Pretendo Network](https://github.com/PretendoNetwork) NEX
libraries (AGPL-3.0).

## Recovered configuration

| Field            | Value |
|------------------|-------|
| Access key       | `a5b77314` (brute-forced, see [docs/access-key-recovery.md](docs/access-key-recovery.md)) |
| NEX library ver. | `3.0.5` |
| PRUDP            | v1, `LegacyConnectionSignature = false` |
| Title IDs        | EUR `0005000010137e00`, USA `0005000010137d00`, JPN `000500001011a800` |
| Game server IDs  | `10137e00` / `10137d00` / `1011a800` |

## Components

- **`wpu-token`** — HTTP account-token issuer. Proxies every ACT request
  upstream except `nex_token/@me` and `service_token/@me` for Wii Party U's
  three title IDs, which it answers locally with a signed token pointing at
  `wpu-nex`. Put the console's ACT host here (directly or behind a reverse
  proxy).
- **`wpu-nex`** — the PRUDPv1 pair: authentication server (default UDP
  `27000`) + secure server (default UDP `27001`). The secure server
  registers secure-connection, utility, NAT traversal and a minimal
  DataStore (`SearchObject` / `GetRatings` / `RateObject`) for the Notes
  bootstrap — see [docs/datastore-tags.md](docs/datastore-tags.md).

Both processes must share `PN_WPU_NEX_TOKEN_AES_KEY` and
`PN_WPU_NEX_PASSWORD_SECRET`.

## Status

Bring-up, not feature-complete. `SearchObject` returns a single placeholder
object (an empty result makes the client leave the screen); ratings are
kept **in memory only** and reset on restart. No database yet.

## Build

```bash
go build -o build/ ./cmd/wpu-token ./cmd/wpu-nex
```

`cmd/capture` and `cmd/bruteforce` are the one-off tools used to recover the
access key; they are not needed to run the server.

## Run

```bash
cp .env.example .env    # fill in the two shared secrets (32-byte hex each)
set -a; . ./.env; set +a

./build/wpu-nex &
./build/wpu-token &
```

Then point the console's account server at `wpu-token` and open the Notes
tab. For a real deployment run both under a supervisor (systemd, etc.) with
the same environment file, and expose the two UDP ports.

## License

AGPL-3.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

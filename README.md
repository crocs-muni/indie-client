Install the `reuirements.txt` and run:
```shell
$ python main.py --username <name>
```

The script first registers a the user `<name>` at the OIDC provider at `http://bias.fi.muni.cz/oidc` and then
allows the OIDC client (audience `zkLogin`) there. Next, a fresh JWT token for the user `<name>` is obtained and sent
to the salt service at `http://bias.fi.muni.cz/salt-service`.

```bash
$ python main.py --username "Firstname Lastname"
{
    "JWT": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImV4YW1wbGUifQ.eyJpc3MiOiJodHRwczovL2F1dGhsaWIub3JnIiwiYXVkIjpbInprTG9naW4iXSwiaWF0IjoxNzQ1NDA4ODY0LCJleHAiOjE3NDU0MTI0NjQsImF1dGhfdGltZSI6MTc0NTQwODg2Mywibm9uY2UiOiJmYjcyMWMxZTUzMzRmOTExOGM5ZWEyOWFiN2IwMGEyM2ZlZTc4M2Q2MmEwZDAzMzI5OGYzZDcxMjJiODEzMjA5IiwiYXRfaGFzaCI6IlVpRTJLYU5zazMyd3c3WkdJdnVIQVEiLCJzdWIiOiIxMiIsIm5hbWUiOiJGaXJzdG5hbWUgTGFzdG5hbWUifQ.R5mkA3iEkpsznDzU-OEgYgurVSiRg4oaHXg0tQWldDOMziwM3--keKjigpDy4ASqLnwFsxAaaKsKJIR2zERx8Q",
    "JWT decoded": {
        "iss": "https://authlib.org",
        "aud": [
            "zkLogin"
        ],
        "iat": 1745408864,
        "exp": 1745412464,
        "auth_time": 1745408863,
        "nonce": "fb721c1e5334f9118c9ea29ab7b00a23fee783d62a0d033298f3d7122b813209",
        "at_hash": "UiE2KaNsk32ww7ZGIvuHAQ",
        "sub": "12",
        "name": "Firstname Lastname"
    },
    "salt": {
        "salt": "6a5323256f3ff924017ae2ebbbd56e2556192e1f322e991b911e56069c17976d"
    },
    "salt via e2ee channel": {
        "salt": "6a5323256f3ff924017ae2ebbbd56e2556192e1f322e991b911e56069c17976d"
    }
}
```

The `salt` values are currently SHA256 hash of the following value (strings encoded using UTF-8):
```
"Salt service" || "zkLogin" || <name> || <32 random bytes>
```

# Have I been pwned - importer

## Why this tool exists

I was curious about the data of the [Have I Been Pwned](https://haveibeenpwned.com/) and wanted to analyze them.
So I have to import them in some kind of database.

Import those amount of data is not a 5min task on standard notebook hardware, but a fun project to see how to do it:

- fast
- reliable
- repeatable
- updatable

And: I wanted to try the `Channel` API of `kotlinx.coroutines`.

## How to use this tool
1. Have a copy of the dataset of [Have I Been Pwned](https://haveibeenpwned.com/) with one file by hash prefix.
   - You may use a tool like [PwnedPasswordsDownloader](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader/)
2. Start a database (currently, mongodb) with `podman` or `docker`
   - possible with `podman compose up -d` or `docker compose up -d` 
3. Configure the [Environment](#environment-variables)

## Environment Variables
| Variable                    | Default Value                               | Description                                             |
|:----------------------------|:--------------------------------------------|:--------------------------------------------------------|
| `MONGODB_CONNECTION_URL`    | `mongodb://admin:admin1234@localhost:27017` | Full qualified connection string                        |
| `PWNED_PASSWORDS_DIRECTORY` |                                             | Full qualified path to all files of `Have I Been Pwned` |




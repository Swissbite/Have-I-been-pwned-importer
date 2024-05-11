# Have I been pwned - importer

A simple importer of all pwned hashes into mongodb.

A personal study of how to import that amount of files as fast and as usable as possible.

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
3. Run the application with all required arguments
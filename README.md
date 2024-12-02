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

And: I wanted to try the `Channel` API of `kotlinx.coroutines` as well the `async` and `launch` options.

## How to use this tool
1. Start a database (currently, mongodb) with `podman` or `docker`
   - possible with `podman compose up -d` or `docker compose up -d` 
2. Run the application. It will ask the following arguments
   1. Where the dataset is or should be cached (path, required)
   2. Mongodb connection
   3. Name of the database
   4. How to import the data
      1. Grouped: A record for each prefix
      2. Single: A record for each single hash
   5. Update / Download from internet
      1. `true` - Will download the data from the internet
      2. `false` - Will use the cached data

## Requirements
- At least 40GB of available storage for the cached files
- Enough disk / memory for the mongoDB
  - The storage for grouped insert is another 41 GB of disk space
  - The storage for single insert is another 70 GB of disk space
  - MongoDB may require several GB of memory
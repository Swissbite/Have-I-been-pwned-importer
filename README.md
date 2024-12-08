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

You can either just download the files from https://haveibeenpwned.com to the directory defined or import them 
a mongodb database

An example mongoDB database is preconfigured within `docker-compose.yml`.



## Requirements
- At least 40GB of available storage for the cached files
- Enough disk / memory for the mongoDB
  - The storage for grouped insert is another 41 GB of disk space
  - The storage for single insert is another 70 GB of disk space
  - MongoDB may require several GB of memory
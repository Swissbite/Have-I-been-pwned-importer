create table hash
(
    hash_prefix CHAR(5)  not null,
    hash_suffix CHAR(36) not null,
    occurrence  INT      not null,
    file_hash   VARCHAR(255)  not null,
    last_update TIMESTAMP not null
);

create index hash_hash_prefix_file_hash_index
    on hash (hash_prefix, file_hash);

create index hash_file_hash_index
    on hash (file_hash);

create index hash_hash_prefix_hash_suffix_index
    on hash (hash_prefix, hash_suffix);

create index hash_occurrence_index
    on hash (occurrence);

create index hash_hash_prefix_occurrence_index
    on hash (hash_prefix, occurrence DESC);

create or replace view hash_prefix_file_hash_count_view as select hash.hash_prefix, hash.file_hash, count(*) as hashes from hash group by hash.hash_prefix, hash.file_hash;
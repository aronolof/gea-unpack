# Working on gea-unpack

Read README.md for the supported formats, API, migration notes and development
commands. Run shell commands from this repository and scope edits to it.

## Public repository boundary

Keep source, examples, tests, documentation and release artifacts generic.
Do not include personal filesystem paths, hostnames, private project names,
customer/dataset details, private fixtures, corpus receipts or recovery notes.
Use synthetic examples and retain required copyright/license attribution.
Keep local reviews, private evidence and backups outside this repository.

## Implementation

Preserve exact volume identities/order, declared extents, moved-tail mapping,
codec history, CRC checks, bounded reads and staged publication. Listing never
extracts files. Publication is atomic per file, not across a whole directory.
Reject unsupported formats explicitly. Application schemas remain downstream.
Preserve existing work before bulk edits. Run tests and lint before committing;
packaging changes also require source/wheel builds and artifact inspection.

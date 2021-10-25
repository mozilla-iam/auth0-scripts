# DEPRECATION NOTICE

*This script has been deprecated. This README is being left intact to support general discovery and decommisioning work.*

# LDAP2S3

This script queries and convert LDAP data from Mozilla LDAP's specific schema to JSON files that get stored in S3
buckets.

# Security

Group data is used for access control and thus important. For that reason, and while there's additional checks made
outside of this script, the script ensures:

- JSON output is signed
- Amount of changes per group since last sync is lower than threshold
- For users that would have the same primary email address in both XXX fixme

# Performance

Due to the group laying in the Mozilla LDAP schema, this script must query all group data, all users, then match user's
dn to group dn, then save the email attribute for these users, which is considered their login.
This takes about 2 or 3 second per query.

To improve performance, batched changes should be only triggered every so often (once per hour or once a day for
example) while otherwise it should be triggered per event with a group filter and aggregated.
This means if 3 group changes for different or the same group happen within a 5s delay, these are aggregated and only
one query is run.

Note as well that fetching images (`jpegPhoto`) is a somewhat slower operation and generates a lot of data (600megs at
the time of writing), and is thus a separate option. It is considered acceptable to run the script with the `-p` (send
pictures to s3) option more rarely. For example you may send the potentially-updated JSON file every minute, but only
send pictures every 15min.

# Usage & Setup

- Create a bucket
- Create an IAM user and associated role & policy so that it can write to the bucket (see `s3_policy.json`)
- Edit ldap2s3.yml (create it if needed by copying the example) and set all parameters
- Generate an AWS access key and run the script (with `-s` to send to S3, `-p` to include pictures): `$ ./ldap2s3.py -s
  -p`

Note: all defaults pertain to Mozilla's specific LDAP setup and will probably not work out of the box elsewhere.

# Mozilla ARNs

- Prod
  - User `arn:aws:iam::371522382791:user/ldap2s3_uploader`
  - Role `arn:aws:iam::371522382791:policy/cis-ldap2s3-publisher-data-write-only-role`
  - Bucket `arn:aws:s3:::cis-ldap2s3-publisher-data`
- Dev
  - User `arn:aws:iam::656532927350:user/ldap2s3_uploader`
  - Role `arn:aws:iam::656532927350:policy/cis-ldap2s3-publisher-data-write-only`
  - Bucket `arn:aws:s3:::dev-cis-ldap2s3-publisher-data`

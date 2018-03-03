# auth0-scripts
Scripts to manage auth0 via API

It also includes other IAM related scripts, such as DuoSecurity scripts that may be useful in combination with IAM or Auth0.

# Scripts

## DuoSecurity
### duo_assign_groups.py
Automatically assign group to new users in Duo. This is used as a default Duo group for all users as Duo cannot do this
automatically.

## LDAP
### disable_deactivated_accounts.py
Automatically set Auth0 'ad' (LDAP) accounts to blocked ('disabled') if they are disabled in LDAP.

### ldap2s3
Uploads LDAP user profile data to an S3 bucket This allows easy access to user profiles in AWS, for example, for CIS.

## authzerolib
A small wrapper library for auth0 management API functions.

## ci
Change Integration - small Auth0 utilities that perform change integration's last steps with Auth0 (i.e. upload code to
Auth0)
These are meant to be used within your existing tests and CI, not as a test or QA harness!

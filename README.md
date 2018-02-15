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

## authzerolib
A small wrapper library for auth0 management API functions.

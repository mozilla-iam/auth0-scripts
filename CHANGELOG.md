# ChangeLog 
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Support for clearpass deprovisioning

### Changed
- Moved authzerolib and ci to https://github.com/mozilla-iam/authzerolib and https://github.com/mozilla-iam/auth0-ci

### Removed
- Removed decommissioned ldap2s3; replaced by `ldap_to_cis` in IAM-858.

## 1.0.0 - 2018-03-02
### Added
- This ChangeLog
- authzerolib support for client updates and basic rules loading
- uploader for auth0 login pages

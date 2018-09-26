# ChangeLog 
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- Support for caching results in ldap2s3 (so that S3 gets updated only if an actual change is detected)
- Support for sending SSH and PGP fingerprints in ldap2s3
- Support for clearpass deprovisioning

### Changed
- Moved authzerolib and ci to https://github.com/mozilla-iam/authzerolib and https://github.com/mozilla-iam/auth0-ci

## 1.0.0 - 2018-03-02
### Added
- This ChangeLog
- authzerolib support for client updates and basic rules loading
- uploader for auth0 login pages

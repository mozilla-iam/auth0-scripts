#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Ah, python2.
global python2_detected
python2_detected = False

import argparse
import boto3
from dotdict import DotDict
import json
from ldap3 import Server, Connection, SUBTREE
try:
    import lzma
except ImportError:
    import backports.lzma as lzma
    python2_detected = True
import logging
import os
import yaml
import sys
import jsonschema

try:
    FileNotFoundError
except NameError:
    python2_detected = True
    FileNotFoundError = IOError


def setup_logging(stream=sys.stderr, level=logging.INFO):
    formatstr="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    logging.basicConfig(format=formatstr, datefmt="%H:%M:%S", stream=stream)
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    return logger


class ldaper():
    def __init__(self, uri, user, password, cis_config):
        global logger
        # This could use the IAM profile eventually if we wanted, with schema validation
        # That said for now we only care about groups

        # Read the user profile in a string but don't parse it yet to avoid having
        # To copy a bunch of dicts, which would cause MemoryError exceptions
        profile_file = cis_config.skeleton
        try:
            with open(profile_file) as fd:
                self.userprofile_json = fd.read()
        except FileNotFoundError:
            logger.critical("FATAL: Could not find default profile file: {}. Please check configuration."
                            .format(profile_file))
            sys.exit(127)
            return # Not reached

        self.cis_config = cis_config

        self.connect(uri, user, password)

    def connect(self, uri, user, password):
        server = Server(uri)
        conn = Connection(server)
        if not conn.bind():
            logger.warning('Anonymous bind failed, cannot connect to the LDAP server')
            raise Exception(AnonymousBindFailed)
        if not conn.start_tls():
            logger.warning('Could not negociate TLS connection with the LDAP server')
            raise Exception(StartTlsFailed)

        if not conn.rebind(user, password):
            logger.warning("Rebind as privileged user failed")
            raise Exception(RebindFailed)

        logger.debug(conn.extend.standard.who_am_i())
        logger.debug(conn)
        self.server = server
        self.conn = conn

    def gfe(self, data, val):
        """
        Get first entry of LDAP result field
        Wrapper that converts to utf-8 and gets the actual first entry of the ldap result list for attributes, as these
        are generate 1 dimension lists.
        """
        myval = data.get(val)
        if type(myval) is list:
            if len(myval) == 0:
                logger.debug('Missing required attribute during conversion of "{}": {}'.format(data, myval))
                return None
            myval = myval[0]

        try:
            ret = myval.decode('utf-8')
        except:
            ret = None
        return ret

    def normalize_ssh(self, sshlist):
        ret = []
        for s in sshlist:
            ss = s.decode('utf-8')
            ret.append(ss.strip(' ').strip('\r\n'))

        return ret

    def normalize_pgp(self, pgplist):
        ret = []
        for s in pgplist:
            ss = s.decode('utf-8')
            tmp = ss.strip(' ').replace(' ', '')
            if tmp.startswith('0x'):
                ret.append(tmp)
            else:
                ret.append('0x{}'.format(tmp))

        return ret

    def validate_user(self, user_profile):
        """
        Validate a user profile against CIS profile
        Returns True if the profile validate, False if not.
        @user_profile: dict
        """
        schema_file = self.cis_config.schema
        try:
            with open(schema_file) as fd:
                schema = json.load(fd)
        except FileNotFoundError:
            return False

        try:
            jsonschema.validate(user_profile, schema)
            return True
        except jsonschema.exceptions.ValidationError as e:
            logger.debug('Validation failure: {}'.format(e))
            return False

    def user(self, entry):
        """
        Finds canonical LDAP data for that user
        """
        user = DotDict(json.loads(self.userprofile_json))

        # Add LDAP attributes
        attrs = entry.get('raw_attributes')
        dn = self.gfe(entry, 'raw_dn')

        # Insert LDAP email as primary email
        user.primary_email.value = self.gfe(attrs, 'mail')
        if not user.primary_email.value or not dn:
            logger.warning('Invalid user specification dn: {} mail: {}'.format(dn, user.primary_email.value))

        # LDAP is our reserved key
        user.identities['values']['LDAP'] = user.primary_email.value

        # Terrible hack to emulate the LDAP user_id
        # This NEEDS to match Auth0 LDAP user_ids
        # XXX Replace this by opaque UUIDs someday, as well as in the Auth0 LDAP Connector
        ldap_user_uid = self.gfe(attrs, 'uid')
        user.usernames['values']['LDAP'] = ldap_user_uid
        user.user_id['value'] = "{}|{}".format(self.cis_config.user_id_prefix, ldap_user_uid)

        # SSH Key
        # Named: "LDAP-1" "LDAP-2", etc.
        n = 0
        for k in self.normalize_ssh(attrs.get('sshPublicKey')):
            n = n + 1
            user.ssh_public_keys['values']['LDAP-{}'.format(n)] = k

        # PGP Key
        # Same naming format as SSH
        n = 0
        for k in self.normalize_pgp(attrs.get('pgpFingerprint')):
            n = n +1
            user.pgp_public_keys['values']['LDAP-{}'.format(n)] = k

        # Phone numbers - note, its not in "telephoneNumber" which is only an extension for VOIP
        phones = attrs.get('mobile')
        n = 0
        for p in phones:
            n = n + 1
            user.phone_numbers['values']['LDAP-{}'.format(n)] = p.decode('utf-8')

        # Names
        user.first_name['value'] = self.gfe(attrs, 'givenName')
        user.last_name['value'] = self.gfe(attrs, 'sn')

        # Times - Profile output format is 2017-03-09T21:28:51.851Z
        dt = entry.get('attributes').get('createTimestamp')
        created = dt.strftime('%Y-%m-%dT:%H:%M:%S.000Z')
        user.created['value'] = created

        dt = entry.get('attributes').get('modifyTimestamp')
        last_modified = dt.strftime('%Y-%m-%dT:%H:%M:%SZ')
        user.last_modified.value = last_modified

        return (dn, user)

    def group(self, entry):
        # Note we cannot rely on the mail= part of the dn here, so we don't
        """
        Finds canonical LDAP data for that group
        """
        group = DotDict(dict())
        attrs = entry.get('raw_attributes')
        group.name = self.gfe(attrs, 'cn')
        group.members = []
        for u in attrs.get('member'):
            group.members.append(u.decode('utf-8'))

        if len(group.members) == 0:
            logger.warning('Empty group for {}'.format(entry.get('raw_dn')))

        return group


if __name__ == "__main__":
    global logger
    os.environ['TZ'] = 'UTC' # Override timezone so we know where we're at
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config', help='Specify a configuration file')
    parser.add_argument('-d', '--debug', action="store_true", help='Turns on debug logging')
    parser.add_argument('-f', '--force', action="store_true", help='Force sending to S3 even if there was no change detected')
    parser.add_argument('-s', '--sends3', action="store_true", help='Sends results to AWS S3 as lzma\'d JSON')
    args = parser.parse_args()
    if args.debug:
        logger = setup_logging(level=logging.DEBUG)
    else:
        logger = setup_logging(level=logging.INFO)
    with open(args.config or 'ldap2s3.yml') as fd:
        config = DotDict(yaml.load(fd))


    mozldap = ldaper(config.ldap.uri, config.ldap.user, config.ldap.password, config.cis)

    # List all groups
    groups = {}
    sgen = mozldap.conn.extend.standard.paged_search(search_base=config.ldap.search_base.groups,
                                                     search_filter=config.ldap.filter.groups,
                                                     attributes = ['cn', 'member'],
                                                     search_scope=SUBTREE, paged_size=10, generator=True)
    for entry in sgen:
        g = mozldap.group(entry)
        groups[g.name] = g.members

    # Find user emails for all users
    users = {}
    sgen = mozldap.conn.extend.standard.paged_search(search_base=config.ldap.search_base.users,
                                                     search_filter=config.ldap.filter.users,
                                                     attributes = ['mail', 'sshPublicKey', 'pgpFingerprint', 'sn',
                                                                   'givenName', 'mobile', 'uid',
                                                                   'createTimestamp', 'modifyTimestamp'],
                                                     search_scope=SUBTREE, paged_size=10, generator=True)
    # Create the list of all users
    for entry in sgen:
        dn, u = mozldap.user(entry)
        users[dn] = u

    # Find which group belongs to which users and add them
    set_userskey = set(users.keys())
    for group in groups:
        uing = set(groups[group]) & set_userskey
        for u in uing:
            # 'null' indicates a new group with no specific value attached to it (ie the group exists)
            users[u]['access_information']['ldap']['values'][group] = 'null'

    logger.debug('Resulting group list:')
    logger.debug(json.dumps(users))

    # Validate all user profiles, warn strongly on failure
    for u in users:
        if not mozldap.validate_user(users[u]):
            logger.critical("Profile schema validation failed for user {} - skipped".format(u))

    # Flatten our list of users into a single json string
    # So this may look a little weird here, let me explain:
    # first, we tell json that we want the 'utf8' encoding. That's because python2 will understand that as actual
    # unicode (utf-8, even). But json has a hardcoded check for 'utf-8' (notice the '-') which doesn't do what you'd
    # expect. This hardcoded check is bypassed since it won't match 'utf8' (no '-')
    # Together with `ensure_ascii=False` this will take the correct code path to return a utf-8 string.
    # Note that because it may also return a non-unicode string if there were no ascii characters found, we also
    # re-encode to utf-8 *again* so that we pass a unicode string back for sure.
    # Finally note that python3's version of json does not have this issue!
    #
    # See also https://stackoverflow.com/questions/18990021/why-python-json-dumps-complains-about-ascii-decoding/50144465
    if python2_detected:
        userlist_json_str = json.dumps(users, encoding="utf8", ensure_ascii=False).encode('utf-8')
    else:
        userlist_json_str = json.dumps(users, ensure_ascii=False).encode('utf-8')

    # Compare with cache
    changes_detected = True # Default to "we have changes" in case cache does not exist
    try:
        with open(config.aws.s3.cache, 'r') as fd:
            cached = json.load(fd)
            if (sorted(cached.items()) == sorted(users.items())):
                logger.debug("No change detected since last run - won't upload to S3")
                changes_detected = False
            else:
                logger.debug("Changes have been detected since last run")
                changes_detected = True
    except FileNotFoundError:
        logger.debug("No cache found, interpreting result as: changes are detected")

    # Write new version to cache
    if changes_detected:
        with open(config.aws.s3.cache, 'wb') as fd:
            fd.write(userlist_json_str)
            logger.debug("Updated cache")

    if args.force:
        logger.warning("Forcing changes_detected to True by user request - this will force S3 uploads even if no changes are present")
        changes_detected = True

    # Dump all this to json => s3
    if args.sends3 and changes_detected:
        logger.debug('Sending results to AWS S3')
        ses = boto3.Session(
                aws_access_key_id=config.aws.boto.access_key_id,
                aws_secret_access_key=config.aws.boto.secret_access_key)
        s3 = ses.client('s3',
                region_name=config.aws.boto.region)
        # We xz compress and send a single file as its vastly faster than sending one file per user (1000x faster)
        xz = lzma.compress(userlist_json_str)
        s3.put_object(Bucket=config.aws.s3.bucket, Key=config.aws.s3.filename, Body=xz)

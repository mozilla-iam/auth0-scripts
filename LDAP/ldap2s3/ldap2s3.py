#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import boto3
from datetime import datetime
import io
import json
from ldap3 import Server, Connection, ALL, SUBTREE
import lzma
import logging
import os
import yaml
import sys

# P2 compat
try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError


def setup_logging(stream=sys.stderr, level=logging.INFO):
    formatstr="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    logging.basicConfig(format=formatstr, datefmt="%H:%M:%S", stream=stream)
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    return logger


class DotDict(dict):
    """
    dict.item notation for dict()'s
    """
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __init__(self, dct):
        for key, value in dct.items():
            if hasattr(value, 'keys'):
                value = DotDict(value)
            self[key] = value

    def __getstate__(self):
        return self.__dict__


class ldaper():
    def __init__(self, uri, user, password):
        global logger
        # This could use the IAM profile eventually if we wanted, with schema validation
        # That said for now we only care about groups
        self.userprofile = {'dn', 'email', 'groups'}
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

    def user(self, entry):
        """
        Finds canonical LDAP data for that user
        """
        user = DotDict(dict())
        attrs = entry.get('raw_attributes')
        user.mail = self.gfe(attrs, 'mail')
        user.dn = self.gfe(entry, 'raw_dn')
        if not user.mail or not user.dn:
            logger.warning('Invalid user specification dn: {} mail: {}'.format(user.dn, user.mail))

        return user

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


    mozldap = ldaper(config.ldap.uri, config.ldap.user, config.ldap.password)

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
                                                     attributes = ['mail'],
                                                     search_scope=SUBTREE, paged_size=10, generator=True)
    for entry in sgen:
        u = mozldap.user(entry)
        users[u.dn] = u.mail

    # Intersect all this to find which users belong to which group
    # Users = {'dn here': 'mail value here', ...}
    # Groups = {'group name here': ['dn here', ...], ...}

    # Create the list of users per groups. We don't actually currently use this.
#    grouplist = {}
#    set_userskey = set(users.keys())
#    for group in groups:
#        uing = set(groups[group]) & set_userskey
#        for u in uing:
#            if not grouplist.get(group):
#                grouplist[group] = []
#            grouplist[group].append(users[u])

    # Same but reverse (find which group belongs to which users). We actually use this ;-)
    userlist = {}
    # Prefill so that we include users with no group data
    for u in users:
        userlist[users[u]] = {'groups': []}
    set_userskey = set(users.keys())
    for group in groups:
        uing = set(groups[group]) & set_userskey
        for u in uing:
            useremail = users[u]
            userlist[useremail]['groups'].append(group)

    logger.debug('Resulting group list:')
    logger.debug(json.dumps(userlist))
    userlist_json_str = json.dumps(userlist, ensure_ascii=False).encode('utf-8')

    # Compare with cache
    changes_detected = True # Default to "we have changes" in case cache does not exist
    try:
        with open(config.aws.s3.cache, 'r') as fd:
            cached = json.load(fd)
            if (sorted(cached.items()) == sorted(userlist.items())):
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
        xz = lzma.compress(userlist_json)
        s3.put_object(Bucket=config.aws.s3.bucket, Key="ldap.json.xz", Body=xz)

#!/usr/bin/env python
# -*- coding: utf-8 -*-

from ldap3 import Server, Connection, SUBTREE
import argparse
import boto3
import json
import lzma
import logging
import cis_profile
import os
import yaml
import sys


def setup_logging(stream=sys.stderr, level=logging.INFO):
    formatstr = "[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    logging.basicConfig(format=formatstr, datefmt="%H:%M:%S", stream=stream)
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    return logger


class ldaper:
    def __init__(self, uri, user, password, cis_config, aws_config, cache):
        global logger
        self.cis_config = cis_config
        self.aws_config = aws_config
        self.connect(uri, user, password)
        self.cache = cache

    def user_from_cache(self, user_dn):
        try:
            user_cached = self.cache[user_dn]
        except KeyError:
            user_cached = None
        return user_cached

    def connect(self, uri, user, password):
        server = Server(uri)
        conn = Connection(server)
        if not conn.bind():
            logger.warning("Anonymous bind failed, cannot connect to the LDAP server")
            raise Exception("AnonymousBindFailed")
        if not conn.start_tls():
            logger.warning("Could not negotiate TLS connection with the LDAP server")
            raise Exception("StartTlsFailed")

        if not conn.rebind(user, password):
            logger.warning("Rebind as privileged user failed")
            raise Exception("RebindFailed")

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
                # This happens too often to even print in debug, but if you need it, its there
                # logger.debug('Missing required attribute during conversion of "{}": {}'.format(data, myval))
                return None
            myval = myval[0]

        try:
            ret = myval.decode("utf-8")
        except:
            ret = None
        return ret

    def normalize_ssh(self, sshlist):
        ret = []
        for s in sshlist:
            ss = s.decode("utf-8")
            ret.append(ss.strip(" ").strip("\r\n"))

        return ret

    def normalize_pgp(self, pgplist):
        ret = []
        for s in pgplist:
            ss = s.decode("utf-8")
            tmp = ss.strip(" ").replace(" ", "")
            if tmp.startswith("0x"):
                ret.append(tmp)
            else:
                ret.append("0x{}".format(tmp))

        return ret

    def user(self, entry):
        """
        Finds canonical LDAP data for that user
        """
        # Get LDAP attributes we'll work on + dn
        attrs = entry.get("raw_attributes")
        dn = self.gfe(entry, "raw_dn")

        # if we have cache, use it
        # else, use a new empty user profile
        # always use schema cache, though, since we loaded it in __init__()
        cached_user = self.user_from_cache(dn)
        if cached_user is not None and len(cached_user) > 1:
            user = cis_profile.User(user_structure_json=cached_user)
        else:
            user = cis_profile.User(user_structure_json_file="data/user_profile_null_create.json")

        # If we have a user, it's active
        user.active.value = True

        # Insert LDAP email as primary email
        user.primary_email.value = self.gfe(attrs, "mail")
        if not user.primary_email.value or not dn:
            logger.warning("Invalid user specification dn: {} mail: {}".format(dn, user.primary_email.value))
        user.identities["mozilla_ldap_primary_email"]["value"] = user.primary_email.value

        # LDAP is our reserved key
        user.identities["mozilla_ldap_id"]["value"] = dn

        # Login method
        user.login_method.value = self.cis_config.connection

        # Terrible hack to emulate the LDAP user_id
        # This NEEDS to match Auth0 LDAP user_ids
        # XXX Replace this by opaque UUIDs someday, as well as in the Auth0 LDAP Connector
        ldap_user_uid = self.gfe(attrs, "uid")
        user.usernames["values"] = {"LDAP": ldap_user_uid}
        user.user_id["value"] = "{}|{}".format(self.cis_config.user_id_prefix, ldap_user_uid)

        n = 0
        for alias in attrs.get("zimbraAlias"):
            n = n + 1
            alias_dec = alias.decode("utf-8")
            user.usernames["values"]["LDAP-alias-{}".format(n)] = alias_dec

        # SSH Key
        # Named: "LDAP-1" "LDAP-2", etc.
        n = 0
        user.ssh_public_keys["values"] = {}
        for k in self.normalize_ssh(attrs.get("sshPublicKey")):
            n = n + 1
            user.ssh_public_keys["values"]["LDAP-{}".format(n)] = k

        # PGP Key
        # Same naming format as SSH
        n = 0
        user.pgp_public_keys["values"] = {}
        for k in self.normalize_pgp(attrs.get("pgpFingerprint")):
            n = n + 1
            user.pgp_public_keys["values"]["LDAP-{}".format(n)] = k

        # Phone numbers - note, its not in "telephoneNumber" which is only an extension for VOIP
        phones = attrs.get("mobile")
        n = 0
        user.phone_numbers["values"] = {}
        for p in phones:
            n = n + 1
            user.phone_numbers["values"]["LDAP-{}".format(n)] = p.decode("utf-8")

        # Names
        user.first_name["value"] = self.gfe(attrs, "givenName")
        user.last_name["value"] = self.gfe(attrs, "sn")
        alternative_name = self.gfe(attrs, "displayName")
        if alternative_name is not None:
            user.alternative_name["value"] = alternative_name

        # Fun title
        user.fun_title.value = self.gfe(attrs, "title")

        # Usernames
        # Unix id / "posix uid" i.e. usernames and their declared integer (eg kang: 1000)
        unix_id = self.gfe(attrs, "uid")
        unix_uid_int = self.gfe(attrs, "uidNumber")
        if unix_id is not None:
            user.usernames["values"] = {"LDAP-posix_id": unix_id, "LDAP-posix_uid": unix_uid_int}
            user.identities["mozilla_posix_id"]["value"] = unix_id
        # other nick/usernames, unverified
        n = 0
        for im_name in attrs.get("im"):
            n = n + 1
            user.usernames["values"]["LDAP-im-unverified-{}".format(n)] = im_name.decode("utf-8")

        # Description / free form text from the user
        description = self.gfe(attrs, "description")
        user.description.value = description

        # Picture - this takes an URI so we're technically correct here, though this isn't exactly usable by all
        # as you need to be able to address the picture URI
        picture = attrs.get("jpegPhoto")
        if picture is not None and len(picture) > 0:
            if not os.path.isdir(self.cis_config.local_pictures_folder):
                os.makedirs(self.cis_config.local_pictures_folder)

            picture_path = "{}/{}.jpg".format(self.cis_config.local_pictures_folder, user.user_id.value)
            # save picture to disk
            with open(picture_path, "wb") as fd:
                fd.write(picture[0])
            picture_uri = "https://s3.amazonaws.com/{}/{}/{}.jpg".format(
                self.aws_config.s3.bucket, self.aws_config.s3.pictures_folder, user.user_id.value
            )
            user.picture.value = picture_uri

        # Check if the created user is different from cache, if not, just use the cache
        # If yes, update timestamps, sign values, validate and replace cache
        # (the sign operation takes significant CPU resources)
        if user.as_dict() == cached_user:
            dict_user = cached_user
        else:
            logger.debug("Cache miss, updating and signing new user data for {}".format(dn))
            if ldap_user_uid is None:
                # This shouldnt happen!
                logger.critical("User does not have a uid in LDAP, something is wrong! dn: {}".format(dn))
                return (dn, None)

            # Times - Profile output format is 2017-03-09T21:28:51.851Z
            dt = entry.get("attributes").get("createTimestamp")
            created = dt.strftime("%Y-%m-%dT:%H:%M:%S.000Z")
            user.created["value"] = created

            dt = entry.get("attributes").get("modifyTimestamp")
            last_modified = dt.strftime("%Y-%m-%dT:%H:%M:%SZ")
            user.last_modified.value = last_modified

            # Update all modified attributes timestamps
            user.initialize_timestamps()

            try:
                user.sign_all(publisher_name="ldap")
            except Exception as e:
                logger.critical(
                    "Profile data signing failed for user {} - skipped signing, verification WILL "
                    "FAIL ({})".format(dn, e)
                )

            # Validate user is correct
            try:
                user.validate()
                # This is a semi-hack (yeah!) which assumes we always publish new profiles. its not true, but we're not
                # the actual publisher, and this will gets us most checks done. i.e. we verify against an empty profile.
                user.verify_all_publishers(cis_profile.User())
            except Exception as e:
                logger.critical("Profile schema validation failed for user {} - skipped".format(dn))
                logger.debug("validation data: {}".format(e))
                return (dn, None)

            dict_user = user.as_dict()

        return (dn, dict_user)

    def group(self, entry):
        # Note we cannot rely on the mail= part of the dn here, so we don't
        """
        Finds canonical LDAP data for that group
        """
        group = cis_profile.DotDict()
        attrs = entry.get("raw_attributes")
        group.name = self.gfe(attrs, "cn")
        group.members = []
        for u in attrs.get("member"):
            group.members.append(u.decode("utf-8"))

        if len(group.members) == 0:
            logger.warning("Empty group for {}".format(entry.get("raw_dn")))

        return group


def cache_load(cache_path):
    cached = {}
    try:
        with open(cache_path, "r") as fd:
            cached = json.load(fd)
    except FileNotFoundError:
        logger.debug("No existing cache found")

    return cached


def cache_write(cache_path, data):
    with open(cache_path, "wb") as fd:
        fd.write(data)


if __name__ == "__main__":
    global logger
    os.environ["TZ"] = "UTC"  # Override timezone so we know where we're at
    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--config", help="Specify a configuration file")
    parser.add_argument("-d", "--debug", action="store_true", help="Turns on debug logging")
    parser.add_argument(
        "-f", "--force", action="store_true", help="Force sending to S3 even if there was no " "change detected"
    )
    parser.add_argument("-s", "--sends3", action="store_true", help="Sends results to AWS S3 as lzma'd JSON")
    parser.add_argument(
        "-p",
        "--sends3pictures",
        action="store_true",
        help="Gets & sends user pictures to AWS S3 " "as well, in jpeg (this is a lot more data)",
    )
    args = parser.parse_args()
    if args.debug:
        logger = setup_logging(level=logging.DEBUG)
    else:
        logger = setup_logging(level=logging.INFO)
    with open(args.config or "ldap2s3.yml") as fd:
        config = cis_profile.DotDict(yaml.load(fd))

    # Load any existing cached data we can use
    cached = cache_load(config.aws.s3.cache)
    mozldap = ldaper(config.ldap.uri, config.ldap.user, config.ldap.password, config.cis, config.aws, cached)

    # List all groups
    groups = {}
    sgen = mozldap.conn.extend.standard.paged_search(
        search_base=config.ldap.search_base.groups,
        search_filter=config.ldap.filter.groups,
        attributes=["cn", "member"],
        search_scope=SUBTREE,
        paged_size=10,
        generator=True,
    )
    for entry in sgen:
        g = mozldap.group(entry)
        groups[g.name] = g.members

    # Find user emails for all users - attributes_to_get are what's actually queried from LDAP
    # See `def user` for how they're parsed and mapped to the IAM profiles
    #
    # zimbraAlias is a list of admin-provided email aliases for the users. The name is historical.
    # im is a list of instant messaging nicknames, usually irc
    # jpegPhoto is raw jpeg data
    # displayName is a custom name (unlike givenName, sn)
    # uid is the posix uid and uidNumber is the posix uid's integer
    # title is an unofficial title set by the user
    users = {}
    attributes_to_get = [
        "mail",
        "sshPublicKey",
        "pgpFingerprint",
        "sn",
        "givenName",
        "mobile",
        "uid",
        "uidNumber",
        "createTimestamp",
        "modifyTimestamp",
        "im",
        "displayName",
        "title",
        "description",
        "zimbraAlias",
    ]
    if args.sends3pictures:
        attributes_to_get.append("jpegPhoto")

    # Lookup all entries in LDAP
    sgen = mozldap.conn.extend.standard.paged_search(
        search_base=config.ldap.search_base.users,
        search_filter=config.ldap.filter.users,
        attributes=attributes_to_get,
        search_scope=SUBTREE,
        paged_size=100,
        generator=True,
    )
    # Create the list of all users
    for entry in sgen:
        # This returns a dn + dict (not JSON)
        dn, u = mozldap.user(entry)
        if u is not None:
            users[dn] = u
            logger.debug("Processed user {}".format(dn))

    # Find which group belongs to which users and add them
    set_userskey = set(users.keys())
    for group in groups:
        uing = set(groups[group]) & set_userskey
        for u in uing:
            # 'null' indicates a new group with no specific value attached to it (ie the group exists)
            if users[u]["access_information"]["ldap"]["values"] is None:
                users[u]["access_information"]["ldap"]["values"] = {}
            users[u]["access_information"]["ldap"]["values"][group] = None

    # Flatten our list of users into a single json string
    # See also:
    # https://stackoverflow.com/questions/18990021/why-python-json-dumps-complains-about-ascii-decoding/50144465
    userlist_json_str = json.dumps(users, ensure_ascii=False).encode("utf-8")

    # Compare with cache
    changes_detected = True  # Default to "we have changes" in case cache does not exist
    if len(cached) > 1:
        if sorted(cached.items()) == sorted(users.items()):
            logger.debug("No change detected since last run - won't upload to S3")
            changes_detected = False

    # Write new version to cache
    if changes_detected:
        cache_write(config.aws.s3.cache, userlist_json_str)
        logger.debug("Updated cache")

    if args.force:
        logger.warning(
            "Forcing changes_detected to True by user request - this will force S3 uploads even if "
            "no changes are present"
        )
        changes_detected = True

    # Dump all this to json => s3
    if args.sends3 and changes_detected:
        logger.debug("Sending results to AWS S3")
        ses = boto3.Session(
            aws_access_key_id=config.aws.boto.access_key_id, aws_secret_access_key=config.aws.boto.secret_access_key
        )
        s3 = ses.client("s3", region_name=config.aws.boto.region)
        # We xz compress and send a single file as its vastly faster than sending one file per user (1000x faster)
        xz = lzma.compress(userlist_json_str)
        s3.put_object(Bucket=config.aws.s3.bucket, Key=config.aws.s3.filename, Body=xz)
        if args.sends3pictures:
            # also send pictures
            logger.debug("Sending pictures to AWS S3 from directory {}".format(config.cis.local_pictures_folder))
            for picture in os.listdir(config.cis.local_pictures_folder):
                p = "{}/{}".format(config.cis.local_pictures_folder, picture)
                if os.path.isfile(p):
                    with open(p, "rb") as fd:
                        picture_data = fd.read()
                    x = s3.put_object(
                        Bucket=config.aws.s3.bucket,
                        Key="{}/{}".format(config.aws.s3.pictures_folder, picture),
                        Body=picture_data,
                    )

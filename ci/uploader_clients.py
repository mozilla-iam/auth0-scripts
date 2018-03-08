#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2017 Mozilla Corporation
# Contributors: Guillaume Destuynder <kang@mozilla.com>

import argparse
import glob
import json
import logging
import os
import sys
from authzero import AuthZero,AuthZeroRule

class DotDict(dict):
    """return a dict.item notation for dict()'s"""

    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __init__(self, dct):
        for key, value in dct.items():
            if hasattr(value, 'keys'):
                value = DotDict(value)
            self[key] = value

if __name__ == "__main__":
    # Logging
    formatstr="[%(asctime)s] %(levelname)s [%(name)s.%(funcName)s:%(lineno)d] %(message)s"
    logging.basicConfig(format=formatstr, datefmt="%H:%M:%S", stream=sys.stdout)
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)

    # Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--uri', default="auth-dev.mozilla.auth0.com", help='URI to Auth0 management API')
    parser.add_argument('-c', '--clientid', required=True, help='Auth0 client id')
    parser.add_argument('-s', '--clientsecret', required=True, help='Auth0 client secret')
    parser.add_argument('-r', '--clients-dir', default='clients', help='Directory containing clients in Auth0 format')
    parser.add_argument('-g', '--get-clients-only', action="store_true",
                        help='Get clients from the Auth0 deployment and write them to disk. This will make NO changes '
                        'to Auth0')
    args = parser.parse_args()

    config = DotDict({'client_id': args.clientid, 'client_secret': args.clientsecret, 'uri': args.uri})
    authzero = AuthZero(config)
    authzero.get_access_token()
    logger.debug("Got access token for client_id:{}".format(args.clientid))

    # on any error, `authzero` will raise an exception and python will exit with non-zero code

    # Remote clients loader
    remote_clients = authzero.get_clients()
    logger.debug("Loaded {} remote clients from current Auth0 deployment".format(len(remote_clients)))

    if not os.path.isdir(args.clients_dir):
        raise Exception('NotAClientsDirectory' (args.clients_dir))

    if args.get_clients_only:
        for client in remote_clients:
            with open("{}/{}.json".format(args.clients_dir, client.get('client_id')), 'w') as fd:
                fd.write(json.dumps(client, indent=4))
                logger.debug("Wrote local client configuration {}".format(client.get('client_id')))
        sys.exit(0)

    # Process all local clients
    local_clients_files = glob.glob("{}/*.json".format(args.clients_dir))
    local_clients = []
    for rfile in local_clients_files:
        logger.debug("Reading local clients configuration {}".format(rfile))
        with open(rfile, 'r') as fd:
            client = DotDict(json.load(fd))

        # Match with existing remote client to see if we need to update
        client_nr = [i for i,_ in enumerate(remote_clients) if _.get('client_id') == client.client_id]
        if client_nr:
            # Just in case we have dupe client_id's (this is not supposed to be possible)
            if (len(client_nr) > 1):
                raise Exception('ClientMatchByIdFailed', (client.name, client_nr))
        else:
            logger.debug('Client only exists locally, considered new and to be created: {}'.format(rule.name))

        local_clients.append(client)
    logger.debug("Found {} local clients".format(len(local_clients)))

    # Find dead clients (i.e. to remove clients that only exist remotely)
    remove_clients = []
    for rl in local_clients:
        ok = False
        for rr in remote_clients:
            if (rl.client_id == rr.get('client_id')):
                ok = True
                continue
        if not ok:
            remove_clients.append(rr)
    logger.debug("Found {} clients that not longer exist locally and will be deleted remotely".format(len(remove_clients)))

    # Update or create (or delete) clients as needed
    for r in remove_clients:
        logger.debug("Removing client {} ({}) from Auth0".format(r.name, r.client_id))
        authzero.delete_client(r.id)

    ## Update & Create (I believe this may be atomic swaps for updates)
    for r in local_clients:
        if not r.client_id:
            logger.debug("Creating new client {} on Auth0".format(r.name))
            noop
            ret = authzero.create_client(r)
            logger.debug("New client created with id {}".format(ret.get('client_id')))
        else:
            logger.debug("Updating client {} ({}) on Auth0".format(r.name, r.client_id))
            authzero.update_client(r.client_id, r)
            noop

    sys.exit(0)

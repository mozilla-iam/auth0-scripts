#!/usr/bin/env python

# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# Copyright (c) 2017 Mozilla Corporation
# Contributors: Guillaume Destuynder <kang@mozilla.com>

import argparse
import json
import logging
import sys
from authzero import AuthZero

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
    parser.add_argument('--default-client', default='VNGM4quJw3Nhx28j8XKVYmu5LcPMCgAH',
                        help='Default Auth0 client id, needed for login page for example')
    parser.add_argument('--login-page', required=True, help='Auth0 hosted login page (HTML)')
    args = parser.parse_args()

    config = DotDict({'client_id': args.clientid, 'client_secret': args.clientsecret, 'uri': args.uri})
    authzero = AuthZero(config)
    authzero.get_access_token()
    logger.debug("Got access token for client_id:{}".format(args.clientid))

    client_attributes = DotDict(dict())
    with open(args.login_page, 'r') as fd:
        client_attributes.custom_login_page = fd.read()
    # on any error, `authzero` will raise an exception and python will exit with non-zero code
    ret = authzero.update_client(args.default_client, client_attributes)
    logger.debug("Default client updated {}".format(ret))
    sys.exit(0)

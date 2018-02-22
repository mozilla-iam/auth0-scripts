#!/usr/bin/env python
# Simple script that list all Duo usrs and check if they are in any of the groups:
# `white_list_groups'. If not, they are added to `group_to_add_to'.
# This can be modified to do a variety of similar things
# It is currently ran manually and is not intended for automatic production purposes in it's current state.
import sys
import os
try:
    import duo_client
# Handle legacy name
except ImportError:
    import duo_client_python as duo_client
import json

config = {}
__location__=os.path.dirname(__file__)
with open(os.path.join(__location__, 'duo_api_settings.json')) as fd:
    config = json.loads(fd.read())

admin_api = duo_client.Admin(
    ikey=config['duo']['ikey'],
    skey=config['duo']['skey'],
    host=config['duo']['api'],
)

users = admin_api.get_users()
white_list_groups = config['groups']['whitelist']
group_to_add_to = config['groups']['add_to']

for user in users:
    grp = admin_api.get_user_groups(user['user_id'])
    foundok = False
    for g in grp:
        if g['group_id'] in white_list_groups:
            foundok = True
            continue
    if not foundok:
        print("{0} {1} is in groups: {2} but not in group {3}, adding.".format(user['username'],
            user['user_id'], str(grp), group_to_add_to))
        admin_api.add_user_group(user['user_id'], group_to_add_to)

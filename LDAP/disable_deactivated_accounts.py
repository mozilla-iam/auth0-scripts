#!/usr/bin/env python
import sys
import optparse
import requests
import ldap
import json

with open('auth0_api_settings.json') as fd:
    config = json.load(fd)
    auth0_config = config['auth0_config']
    ldap_config = config['ldap_config']
    proxy_config = config['proxy_config']
    disable_deactivated_accounts_config = config['disable_deactivated_accounts_config']

# function to build headers that'll be used by all API calls
def build_headers():
    headers = {}
    headers['Authorization'] = 'Bearer %s' % auth0_config['auth0_api_key']
    headers['Content-Type'] = "application/json"
    headers['Accept'] = "application/json"
    return headers

# generic function to just get all users belonging to the specific enterprise connection
# it has some logic to page through a list longer than 50, stolen from the Okta version of this script, needs tested once we have more users
def list_all_users():
    should_return = False
    return_list = []
    fetch_url = "%s/users" % auth0_config['auth0_api_url']
    payload = {'fields': 'identities,user_id,email,blocked', 'include_fields': 'true'}
    while (should_return is False):
        prev_url = fetch_url
        if proxy_config['use_proxy'] is True:
            resp = requests.get(
                fetch_url,
                headers=build_headers(),
                params=payload,
                proxies=proxy_config['proxies']
            )
            if resp.status_code != 200:
                print("Error while getting users from Auth0")
                print("{code}{text}".format(code=resp.status_code, text=resp.text))
        else:
            resp = requests.get(fetch_url, headers=build_headers(), params=payload)
            if resp.status_code != 200:
                print("Error while getting users from Auth0")
                print("{code}{text}".format(code=resp.status_code, text=resp.text))
        return_list += resp.json()
        try:
            fetch_url = resp.links['next']['url']
            if fetch_url == '' or fetch_url is None or fetch_url == prev_url:
                should_return = True
        except (KeyError, IndexError):
            should_return = True
    return return_list

# filter out only the active users
# active user here is defined as not being currently blocked
def list_active_users(users):
    ret_users = []
    for user in users:
        if user.get(u'blocked') is not True:
            ret_users.append(user)
    return ret_users

# also need a list of blocked users to see if they should be unblocked
def list_blocked_users(users):
    ret_users = []
    for user in users:
        if user.get(u'blocked') is True:
            ret_users.append(user)
    return ret_users

#    return [user for user in users if u'blocked' not in user or user[u'blocked'] != True]

# this function returns the DN of the user that matches the given e-mail address
def get_ldap_user_by_mail(conn, mail):
    mail_attribute = ldap_config['mail_attribute']
    alias_attribute = ldap_config['alias_attribute']
    mail_query = '(|(%s=%s)(%s=%s))' % (mail_attribute, mail, alias_attribute, mail)
    disabled_query = ldap_config['disabled_query']
    member = conn.search_s('dc=mozilla',
                           ldap.SCOPE_SUBTREE,
                           '(&%s(!(%s)))' % (mail_query, disabled_query),
                           attrlist=['mail'])
    if len(member) == 1:
        try:
            if member[0][1]['mail'][0]:
                return True
            else:
                return False
        except (IndexError, KeyError):
            return None
    elif len(member) == 0:
        return False
    else:
        print("Something went wrong and we got {number} entries and expected 0 or 1".format(number=len(member)))
        sys.exit(2)

# this function does the actual blocking of the user in auth0
def disable_user(user_id):
    deactive_url = "users/%s" % user_id
    url = "%s/%s" % (auth0_config['auth0_api_url'], deactive_url)
    body = '{"blocked":true}'
    if proxy_config['use_proxy'] is True:
        resp = requests.patch(url, headers=build_headers(), data=body, proxies=proxy_config['proxies'])
        if resp.status_code != 200:
            print("Error while blocking {user}:".format(user=user_id))
            print("{code}{text}".format(code=resp.status_code, text=resp.text))
    else:
        resp = requests.patch(url, headers=build_headers(), data=body)
        if resp.status_code != 200:
            print("Error while blocking {user}:".format(user=user_id))
            print("{code}{text}".format(code=resp.status_code, text=resp.text))
    return True

# this function does the unblocking of the user in auth0
def unblock_user(user_id):
    deactive_url = "users/%s" % user_id
    url = "%s/%s" % (auth0_config['auth0_api_url'], deactive_url)
    body = '{"blocked":false}'
    if proxy_config['use_proxy'] is True:
        resp = requests.patch(url, headers=build_headers(), data=body, proxies=proxy_config['proxies'])
        if resp.status_code != 200:
            print("Error while unblocking {user}:".format(user=user_id))
            print("{code}{text}".format(code=resp.status_code, text=resp.text))
    else:
        resp = requests.patch(url, headers=build_headers(), data=body)
        if resp.status_code != 200:
            print("Error while unblocking {user}:".format(user=user_id))
            print("{code}{text}".format(code=resp.status_code, text=resp.text))
    return True


# main function with logic to get all the active users in auth0, check if they exist in LDAP and not disabled, then disable if not found
# note that a user that does not exist in LDAP is equivalent to a user that is DISABLED in LDAP, due to ACLs. This cannot be distinguished without special permissions
# if a user is blocked in Auth0, but no longer disabled in LDAP, then unblock the user
def main(prog_args=None):
    if prog_args is None:
        prog_args = sys.argv

    parser = optparse.OptionParser()
    parser.usage = """Script to disable auth0 accounts if not found in LDAP and unblock previously disabled LDAP users"""
    parser.add_option("-d", "--debug", dest="debug", action="store_true",
                      help="Run in DEBUG/NOOP Mode")

    opt, args = parser.parse_args(sys.argv[1:])

    all_users = list_all_users()

    active_users = list_active_users(all_users)

    block_users = list_blocked_users(all_users)

    ldap_conn = ldap.initialize('ldap://%s' % ldap_config['ldap_host'])
    ldap_conn.simple_bind_s(ldap_config['ldap_user'], ldap_config['ldap_pass'])

    for user in active_users:
        try:
            email = user.get(u'email')
        except (KeyError):
            print("Cannot get email attribute for user")

        try:
            identity = user.get(u'user_id')
        except (KeyError):
            print("Cannot get id attribute for user")
            continue

        if identity and email:
            for domain in ldap_config['ldap_domains']:
                if domain in email:
                    if get_ldap_user_by_mail(ldap_conn, email) is not True\
                            and email not in disable_deactivated_accounts_config['exclusion_list']:
                        print("Disabling Auth0 for {user}".format(user=email))
                        if not opt.debug:
                            disable_user(identity)

    for user in blocked_users:
        try:
            email = user.get(u'email')
        except (KeyError):
            print("Cannot get email attribute for user")

        try:
            identity = user.get(u'user_id')
        except (KeyError):
            print("Cannot get id attribute for user")
            continue

        if identity and email:
            for domain in ldap_config['ldap_domains']:
                if domain in email:
                    if get_ldap_user_by_mail(ldap_conn, email) is True\
                            and email not in disable_deactivated_accounts_config['exclusion_list']:
                        print("Re-enabling Auth0 for {user}".format(user=email))
                        if not opt.debug:
                            unblock_user(identity)


if __name__ == "__main__":
    main()

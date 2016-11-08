#!/usr/bin/python
import sys
import optparse
import requests
import ldap
import json

from auth0_api_settings import AUTH0_API_KEY, AUTH0_API_URL, AUTH0_CONNECTION, LDAP_HOST,\
    LDAP_USER, LDAP_PASS, EXCLUSION_LIST, USE_PROXY, PROXIES

# function to build headers that'll be used by all API calls
def build_headers():
    headers = {}
    headers['Authorization'] = 'Bearer %s' % AUTH0_API_KEY
    headers['Content-Type'] = "application/json"
    headers['Accept'] = "application/json"
    return headers

# generic function to just get all users belonging to the specific enterprise connection
# it has some logic to page through a list longer than 50, stolen from the Okta version of this script, needs tested once we have more users
def list_all_users():
    should_return = False
    return_list = []
    fetch_url = "%s/users" % (AUTH0_API_URL)
    payload = {'connection': "%s" % AUTH0_CONNECTION, 'fields': 'user_id,email,blocked', 'include_fields': 'true'}
    while (should_return is False):
        prev_url = fetch_url
        if USE_PROXY is True:
            resp = requests.get(
                fetch_url,
                headers=build_headers(),
                params=payload,
                proxies=PROXIES
            )
        else:
            resp = requests.get(fetch_url, headers=build_headers(), params=payload)
            req = resp.request
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
def list_all_active_users():
    users = list_all_users()
    return [user for user in users if user[u'blocked'] != True]


# this function returns the DN of the user that matches the given e-mail address
def get_ldap_user_by_mail(conn, mail):
    member = conn.search_s('dc=mozilla',
                           ldap.SCOPE_SUBTREE,
                           '(&(mail=%s)(!(employeeType=DISABLED)))' % mail,
                           attrlist=['mail'])
    try:
        if member[0][1]['mail'][0]:
            return True
        else:
            return False
    except (IndexError, KeyError):
        return None

# this function does the actual blocking of the user in auth0
def disable_user(user_id):
    deactive_url = "users/%s" % user_id
    url = "%s/%s" % (AUTH0_API_URL, deactive_url)
    body = '{"blocked":true}'
    if USE_PROXY is True:
        requests.patch(url, headers=build_headers(), data=body, proxies=PROXIES)
    else:
        requests.patch(url, headers=build_headers(), data=body)
    return True


# main function with logic to get all the active users in auth0, check if they exist in LDAP and not disabled, then disable if not found
# note that a user that does not exist in LDAP is equivalent to a user that is DISABLED in LDAP, due to ACLs. This cannot be distinguished without special permissions
def main(prog_args=None):
    if prog_args is None:
        prog_args = sys.argv

    parser = optparse.OptionParser()
    parser.usage = """Script to disable auth0 accounts if not found in LDAP"""
    parser.add_option("-d", "--debug", dest="debug", action="store_true",
                      help="Run in DEBUG/NOOP Mode")

    opt, args = parser.parse_args(sys.argv[1:])

    active_users = list_all_active_users()

    ldap_conn = ldap.initialize('ldap://%s' % LDAP_HOST)
    ldap_conn.simple_bind_s(LDAP_USER, LDAP_PASS)

    for user in active_users:
        try:
            email = user['email']
        except (KeyError):
            print "Cannot get email attribute for user"

        try:
            id = user['user_id']
        except (KeyError):
            print "Cannot get id attribute for user"

        if id and email:
            active_ldap_account = get_ldap_user_by_mail(ldap_conn, email)
            if active_ldap_account is not True\
                    and email not in EXCLUSION_LIST:
                print "Disabling Auth0 for %s" % email
                if not opt.debug:
                    disable_user(id)


if __name__ == "__main__":
    main()

#!/usr/bin/env python
import os
import sys
import optparse
import requests
import ldap
import json

__location__=os.path.dirname(__file__)
with open(os.path.join(__location__, 'auth0_api_settings.json')) as fd:
    config = json.load(fd)
    ldap_config = config['ldap_config']
    clearpass_config = config['clearpass_config']
    proxy_config = config['proxy_config']
    disable_deactivated_accounts_config = config['disable_deactivated_accounts_config']

# this function returns the DN of the user that matches the given e-mail address
def get_ldap_user_by_mail(conn, mail):
    mail_attribute = ldap_config['mail_attribute']
    alias_attribute = ldap_config['alias_attribute']
    mail_query = '(|(%s=%s)(%s=%s))' % (mail_attribute, mail, alias_attribute, mail)
    disabled_query = ldap_config['disabled_query']
    clearpass_group_query = ldap_config['clearpass_group_query']
    member = conn.search_s('dc=mozilla',
                           ldap.SCOPE_SUBTREE,
                           '(&%s(!(%s)%s))' % (mail_query, disabled_query, clearpass_group_query),
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

class Clearpass(object):
    def __init__(self, uri, client_id, client_secret, proxies=None):
        self.uri = uri
        self._client_id = client_id
        self._client_secret = client_secret
        self.proxies = proxies
        self.token = self.authorize()

    def authorize(self):
        """
        See https://clearpass.mozilla.net/api-docs/ApiFramework-v1
        """
        payload = {'client_id': self._client_id,
                   'client_secret': self._client_secret,
                   'grant_type': 'client_credentials'
                  }
        r = requests.post('{}{}'.format(self.uri, 'oauth'),
                          data=payload,
                          proxies=self.proxies)
        if not r.ok:
            raise Exception('RequestFailed', r.reason)
        return r.json()

    def build_headers(self):
        headers = {}
        headers['Authorization'] = 'Bearer {}'.format(self.token['access_token'])
        headers['Content-Type'] = "application/json"
        headers['Accept'] = "application/json"
        return headers

    def list_users(self, role_filter="[Employee]"):
        """
        See https://clearpass.mozilla.net/api/apigility/swagger/Identity-v1 (LocalUser)
        """
        cpfilter = '{"role_name":"%s"}' % role_filter
        payload = {'offset': '0', 'limit': '1000', 'calculate_count': 'true', 'filter': cpfilter}
        r = requests.get('{}{}'.format(self.uri, 'local-user'),
                         headers=self.build_headers(),
                         params=payload,
                         proxies=self.proxies)

        if not r.ok:
            print(r.text)
            raise Exception('RequestFailed', r.reason)

        return r.json()['_embedded']['items']

    def remove_user(self, user_id):
        """
        See https://clearpass.mozilla.net/api/apigility/swagger/Identity-v1 (LocalUser delete by user id)
        """
        payload = {'user_id': user_id}
        r = requests.delete('{}{}'.format(self.uri, 'local-user'),
                headers=self.build_headers(),
                params=payload,
                proxies=self.proxies)
        if not r.ok:
            print(r.text)
            raise Exception('RequestDeleteFailed', r.reason)
        return r.json()

# main function with logic to get all the active users in auth0, check if they exist in LDAP and not disabled, then disable if not found
# note that a user that does not exist in LDAP is equivalent to a user that is DISABLED in LDAP, due to ACLs. This cannot be distinguished without special permissions
# if a user is blocked in Auth0, but no longer disabled in LDAP, then unblock the user
def main(prog_args=None):
    if prog_args is None:
        prog_args = sys.argv

    parser = optparse.OptionParser()
    parser.usage = """Script to disable clearpass (wifi) accounts if not found in LDAP"""
    parser.add_option("-d", "--debug", dest="debug", action="store_true",
                      help="Run in DEBUG/NOOP Mode")

    opt, args = parser.parse_args(sys.argv[1:])

    if proxy_config['use_proxy'] == 'true':
        proxies = proxy_config['proxies']
    else:
        proxies = None

    clearpass_client = Clearpass(clearpass_config['uri'],
                                 clearpass_config['client_id'],
                                 clearpass_config['client_secret'],
                                 proxies)
    active_users = clearpass_client.list_users(role_filter=clearpass_config['role_filter'])

    ldap_conn = ldap.initialize('ldap://%s' % ldap_config['ldap_host'])
    ldap_conn.simple_bind_s(ldap_config['ldap_user'], ldap_config['ldap_pass'])

    for user in active_users:
        if opt.debug:
            print("Verifying user", user['username'])
        try:
            #clearpass_username is an email
            clearpass_username = user.get(u'username')
            clearpass_email_domain = clearpass_username.split('@')[1]
        except (KeyError, AttributeError):
            print("Cannot get email attributes for user", user)

        try:
            clearpass_uid = user.get(u'id')
        except (KeyError):
            print("Cannot get id attribute for user", user)
            continue

        if clearpass_uid and clearpass_username:
            for domain in ldap_config['ldap_domains']:
                if domain in clearpass_email_domain:
                    if (get_ldap_user_by_mail(ldap_conn, clearpass_username) is not True) \
                       and (clearpass_username not in disable_deactivated_accounts_config['exclusion_list']):
                        print("Disabling clearpass (wifi) for {user}".format(user=email))
                        if not opt.debug:
                            clearpass_client.remove_user(identity)

if __name__ == "__main__":
    main()

#!/usr/bin/python
import ldap
DEBUG = False
NOOP = False
from local_settings import (
    LDAP_HOST,
    LDAP_USERNAME,
    LDAP_PASSWORD,
    GRACE_PERIOD
)

from duo_settings import (
    DUO_ADMIN_API_HOST,
    DUO_ADMIN_API_IKEY,
    DUO_ADMIN_API_SKEY
)

from duo_client_python.admin import Admin
admin_api = Admin(
    ikey=DUO_ADMIN_API_IKEY,
    skey=DUO_ADMIN_API_SKEY,
    host=DUO_ADMIN_API_HOST)

def get_duo_usernames():
    ret_list = []
    for user in admin_api.get_users():
        # We only care about user accounts that are
        if user['status'] != u"disabled":
            ret_list.append({
                'email_address': user['username'],
                'id': user['user_id'],
                'status': user['status'],
            })
    return ret_list

def get_disabled_duo_usernames():
    ret_list = []
    for user in admin_api.get_users():
        # We only care about user accounts that are
        if user['status'] == u"disabled":
            ret_list.append({
                'email_address': user['username'],
                'id': user['user_id'],
                'status': user['status'],
                'last_login': user['last_login']
            })
    return ret_list

def get_ldap_user_by_mail(ldap_conn, email):
    try:
        user_obj = ldap_conn.search_s(
            'dc=mozilla',
            ldap.SCOPE_SUBTREE,
            '(mail=%s)' % email,
            attrlist=['mail']
        )
    except (ldap.NO_SUCH_OBJECT):
        return False
    try:
        return 'mail' in user_obj[0][1]
    except (IndexError, AttributeError):
        return False


if __name__ == '__main__':
    ldap_conn = ldap.initialize('ldap://%s' % LDAP_HOST)
    ldap_conn.simple_bind_s(LDAP_USERNAME, LDAP_PASSWORD)

    all_duo_usernames = get_duo_usernames()
    all_disabled_duo_usernames = get_disabled_duo_usernames()

    # Disable whoever should be disabled
    for duo_entry in all_duo_usernames:
        duo_email = duo_entry['email_address']
        duo_user_id = duo_entry['id']
        found = get_ldap_user_by_mail(ldap_conn, duo_email)
        if found is True:
            if DEBUG:
                print "%s found" % duo_email
        else:
            print "Disabling %s with ID %s from duo. Not found in LDAP"\
                  % (duo_email, duo_user_id)
            if NOOP == False:
                admin_api.update_user(duo_user_id, status='disabled')

    # Delete users that have been disabled and haven't logged in for GRACE_PERIOD seconds (licenses)
    for duo_entry in all_disabled_duo_usernames:
        last_login = duo_entry.get('last_login')
        if last_login:
            unix_last_login = int(last_login)
            if int(time.time()) - unix_last_login > GRACE_PERIOD:
                print("Deleting user {} ID {}".format(duo_entry.get('email_address'), duo_entry.get('id')))
                if NOOP == False:
                    admin_api.delete_user(duo_entry.get('id'))

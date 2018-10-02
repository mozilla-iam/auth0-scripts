{
    "ldap_config": {
        "ldap_user": "",
        "ldap_pass": "",
        "ldap_host": "",
        "mail_attribute": "mail",
        "disabled_query": "employeeType=DISABLED",
        "clearpass_group_query": "(|(cn=team_moco)(cn=team_mofo)(cn=wifi_non_staff))"
    },
    "proxy_config": {
        "use_proxy": false,
        "proxies": {
            "http": "http://proxy.dmz.mdc1.mozilla.com:3128",
            "https": "http://proxy.dmz.mdc1.mozilla.com:3128"
        }
    },
    "clearpass_config": {
      "uri": "https://clearpass.mozilla.net/api/",
      "client_id": "",
      "client_secret": "",
      "role_filter": "[Employee]"
	},
    "disable_deactivated_accounts_config": {
        "exclusion_list": [
            "example@mozilla.com",
            "example2@mozilla.com"
        ]
    }
}

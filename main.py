import ldap
from secret import *
#vars
#ad_server = 'ldap://'your_ip_or_fqdn':389'
ad_server = "ldaps://'your_ip_or_fqdn':636"
#user DN in LDAP
#user_dn = 'CN={0},OU=test,DC=example,DC=ru'
user_dn = ''user_dn''
#user OU in LDAP (all users, which will can change youself password are here)
base_dn = ''base_dn''
search_scope = ldap.SCOPE_SUBTREE
#retrieve Certain attributes
retrieve_attributes = ["mobile","mail","cn"]
#This searchFilter needs to be more specific
samaccoutname = ''samaccoutname''
search_filter = f'(&(sAMAccountName={samaccoutname})(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(mail=* @example.ru)(mobile=8*))'


def ldap_connect():
    try:
        # Force cert validation
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        # Declare global var l
        global l
        # LDAP connection initialization
        l = ldap.initialize(ad_server)
        l.set_option(ldap.OPT_REFERRALS, 0)
        # Set LDAP protocol version used
        l.set_option(ldap.OPT_PROTOCOL_VERSION, 3)
        l.set_option(ldap.OPT_X_TLS, ldap.OPT_X_TLS_DEMAND)
        l.set_option(ldap.OPT_X_TLS_DEMAND, True)
        l.set_option(ldap.OPT_DEBUG_LEVEL, 255)
        # Bind (as admin user)
        l.simple_bind_s(admin_username, admin_password)
        print("Connected!")
    except Exception as ex:
        print(ex)

# Check user status in LDAP (enabled or disabled)
def check_user():
    ldap_check_user = l.search_s(base_dn, search_scope, search_filter, retrieve_attributes)
    cn = ldap_check_user[0][-1]['cn'][0].decode('UTF-8')
    mobile = ldap_check_user[0][-1]['mail'][0].decode('UTF-8')
    mail = ldap_check_user[0][-1]['mobile'][0].decode('UTF-8')
    print(cn, mobile, mail)

# Verifi user (capcha and sms code)
def verifi_user():
    pass

# Change password
def change_password():
    # Now, perform the password update
    newpwd_utf16 = '"{0}"'.format(new_user_pwd).encode('utf-16-le')
    mod_list = [(ldap.MOD_REPLACE, "unicodePwd", newpwd_utf16),]
    l.modify_s(user_dn.format(username), mod_list)

# Close connection
def close_ldap_session():
    l.unbind_s()


# Run script
if __name__ == '__main__':
    ldap_connect()
    check_user()
    close_ldap_session()
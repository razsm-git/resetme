import ldap

#vars
#ad_server = 'ldap://'your_ip_or_fqdn':389'
ad_server = "ldaps://'your_ip_or_fqdn':636"
#где лежит юзер
#ad_dn = 'CN={0},OU=test,DC=example,DC=ru'
ad_dn = 'CN={0},OU=Users,DC='',DC=ru'

#admin_username = 's_resetme@your_domain'
admin_username = "'your_login_here'"
admin_password = "'passwod'"

username = ''samaccoutname''
new_pwd = ''your_password_here''

try:
    # Force cert validation
    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
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

# Now, perform the password update
newpwd_utf16 = '"{0}"'.format(new_pwd).encode('utf-16-le')
mod_list = [(ldap.MOD_REPLACE, "unicodePwd", newpwd_utf16),]
lconn.modify_s(ad_dn.format(username), mod_list)
import ldap

#vars
#нужно ли порт указывать?
ad_server = 'ldap://'your_ip_or_fqdn':389'
#где лежит юзер
ad_dn = 'CN={0},OU=test,DC=example,DC=ru'

admin_username = 's_resetme@your_domain'
admin_password = ''passwod''

username = ''samaccoutname''
new_pwd = ''your_password_here''

try:
    # LDAP connection initialization
    lconn = ldap.initialize(ad_server)
    # Set LDAP protocol version used
    lconn.protocol_version = ldap.VERSION3
    lconn.set_option(ldap.OPT_REFERRALS, 0)
    # Bind (as domain admin user)
    lconn.simple_bind_s(admin_username, admin_password)
    print("Connected!")
except ldap.SERVER_DOWN:
    print("Error connection to AD")


# cert = os.path.join('/path', "to", 'server_cert.cer')

# # LDAP connection initialization
# l = ldap.initialize(ad_server)
# # Set LDAP protocol version used
# l.protocol_version = ldap.VERSION3
# # Force cert validation
# l.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_DEMAND)
# # Set path name of file containing all trusted CA certificates
# l.set_option(ldap.OPT_X_TLS_CACERTFILE, cert)
# # Force libldap to create a new SSL context (must be last TLS option!)
# l.set_option(ldap.OPT_X_TLS_NEWCTX, 0)

# # Bind (as admin user)
# l.simple_bind_s(ad_dn.format(admin_username), admin_password)

# # Now, perform the password update
newpwd_utf16 = '"{0}"'.format(new_pwd).encode('utf-16-le')
mod_list = [(ldap.MOD_REPLACE, "unicodePwd", newpwd_utf16),]
lconn.modify_s(ad_dn.format(username), mod_list)
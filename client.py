import ldap

try:
    lconn = ldap.initialize('ldap://dc1.your_domain:389')
    lconn.protocol_version = ldap.VERSION3
    lconn.set_option(ldap.OPT_REFERRALS, 0)
    lconn.simple_bind_s(''your_login_here'', ''your_password_here'')
    print("Connected user!")
except ldap.SERVER_DOWN:
    print("Error connection to AD")
import ldap
from secret import *

#vars
#ad_server = 'ldap://'your_ip_or_fqdn':389'
ad_server = "ldaps://'your_ip_or_fqdn':636"

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
    l.simple_bind_s(user_name, user_pwd)
    print("Client connected!")
    # Close connection
    l.unbind_s()
except Exception as ex:
    print(ex)
# Set the Hub to listen on all interfaces in the container on port 8000
c.JupyterHub.ip = '0.0.0.0'
c.JupyterHub.port = 8000

# The authenticator can call pam_open_session before spawning a notebook server
# and pam_close_session when shutting one down. With pam_krb5, this results
# in a log message stating:
    # Nov 15 14:22:28 workbook python: pam_krb5(login:session):
    # (user bob) unable to get PAM_KRB5CCNAME, assuming non-Kerberos login
# most likely because the pam_authentication and pam_setcreds calls are
# happening in a wholly separate pam transaction where the env var is set.
# So opening sessions has no impact on Kerberos ticketing in the current Hub
# design for auth and spawn.
c.PAMAuthenticator.open_sessions = False

import ldap3
import re

from tornado import gen

from jupyterhub.auth import Authenticator
import pamela
from traitlets import Unicode, Int, Bool, List, Union

class KerberosPAMwithLDAPAuthenticator(Authenticator):
    # PAM part
    """Authenticate local UNIX users with PAM"""

    encoding = Unicode('utf8',
        help="""
        The text encoding to use when communicating with PAM
        """
    ).tag(config=True)

    service = Unicode('login',
        help="""
        The name of the PAM service to use for authentication
        """
    ).tag(config=True)

    open_sessions = Bool(True,
        help="""
        Whether to open a new PAM session when spawners are started.
        This may trigger things like mounting shared filsystems,
        loading credentials, etc. depending on system configuration,
        but it does not always work.
        If any errors are encountered when opening/closing PAM sessions,
        this is automatically set to False.
        """
    ).tag(config=True)

    def pre_spawn_start(self, user, spawner):
        """Open PAM session for user if so configured"""
        if not self.open_sessions:
            return
        try:
            pamela.open_session(user.name, service=self.service)
        except pamela.PAMError as e:
            self.log.warning("Failed to open PAM session for %s: %s", user.name, e)
            self.log.warning("Disabling PAM sessions from now on.")
            self.open_sessions = False

    def post_spawn_stop(self, user, spawner):
        """Close PAM session for user if we were configured to opened one"""
        if not self.open_sessions:
            return
        try:
            pamela.close_session(user.name, service=self.service)
        except pamela.PAMError as e:
            self.log.warning("Failed to close PAM session for %s: %s", user.name, e)
            self.log.warning("Disabling PAM sessions from now on.")
            self.open_sessions = False
    
    # LDAP part
        server_address = Unicode(
        config=True,
        help="""
        Address of the LDAP server to contact.
        Could be an IP address or hostname.
        """
    )
    server_port = Int(
        config=True,
        help="""
        Port on which to contact the LDAP server.
        Defaults to `636` if `use_ssl` is set, `389` otherwise.
        """
    )

    def _server_port_default(self):
        if self.use_ssl:
            return 636  # default SSL port for LDAP
        else:
            return 389  # default plaintext port for LDAP

    use_ssl = Bool(
        True,
        config=True,
        help="""
        Use SSL to communicate with the LDAP server.
        Highly recommended! Your LDAP server must be configured to support this, however.
        """
    )

    bind_dn_template = Union(
        [List(),Unicode()],
        config=True,
        help="""
        Template from which to construct the full dn
        when authenticating to LDAP. {username} is replaced
        with the actual username used to log in.
        If your LDAP is set in such a way that the userdn can not
        be formed from a template, but must be looked up with an attribute
        (such as uid or sAMAccountName), please see `lookup_dn`. It might
        be particularly relevant for ActiveDirectory installs.
        Unicode Example:
            uid={username},ou=people,dc=wikimedia,dc=org
        
        List Example:
            [
            	uid={username},ou=people,dc=wikimedia,dc=org,
            	uid={username},ou=Developers,dc=wikimedia,dc=org
        	]
        """
    )

    allowed_groups = List(
        config=True,
        allow_none=True,
        default=None,
        help="""
        List of LDAP group DNs that users could be members of to be granted access.
        If a user is in any one of the listed groups, then that user is granted access.
        Membership is tested by fetching info about each group and looking for the User's
        dn to be a value of one of `member` or `uniqueMember`, *or* if the username being
        used to log in with is value of the `uid`.
        Set to an empty list or None to allow all users that have an LDAP account to log in,
        without performing any group membership checks.
        """
    )

    # FIXME: Use something other than this? THIS IS LAME, akin to websites restricting things you
    # can use in usernames / passwords to protect from SQL injection!
    valid_username_regex = Unicode(
        r'^[a-z][.a-z0-9_-]*$',
        config=True,
        help="""
        Regex for validating usernames - those that do not match this regex will be rejected.
        This is primarily used as a measure against LDAP injection, which has fatal security
        considerations. The default works for most LDAP installations, but some users might need
        to modify it to fit their custom installs. If you are modifying it, be sure to understand
        the implications of allowing additional characters in usernames and what that means for
        LDAP injection issues. See https://www.owasp.org/index.php/LDAP_injection for an overview
        of LDAP injection.
        """
    )

    lookup_dn = Bool(
        False,
        config=True,
        help="""
        Form user's DN by looking up an entry from directory
        By default, LDAPAuthenticator finds the user's DN by using `bind_dn_template`.
        However, in some installations, the user's DN does not contain the username, and
        hence needs to be looked up. You can set this to True and then use `user_search_base`
        and `user_attribute` to accomplish this.
        """
    )

    user_search_base = Unicode(
        config=True,
        default=None,
        allow_none=True,
        help="""
        Base for looking up user accounts in the directory, if `lookup_dn` is set to True.
        LDAPAuthenticator will search all objects matching under this base where the `user_attribute`
        is set to the current username to form the userdn.
        For example, if all users objects existed under the base ou=people,dc=wikimedia,dc=org, and
        the username users use is set with the attribute `uid`, you can use the following config:
        ```
        c.LDAPAuthenticator.lookup_dn = True
        c.LDAPAuthenticator.user_search_base = 'ou=people,dc=wikimedia,dc=org'
        c.LDAPAuthenticator.user_attribute = 'uid'
        ```
        """
    )

    user_attribute = Unicode(
        config=True,
        default=None,
        allow_none=True,
        help="""
        Attribute containing user's name, if `lookup_dn` is set to True.
        See `user_search_base` for info on how this attribute is used.
        For most LDAP servers, this is uid.  For Active Directory, it is
        sAMAccountName.
        """
    )
    
    # PAM part
    @gen.coroutine
    def authenticate(self, handler, data):
        username = data['username']
        password = data['password']
        # Get LDAP Connection
        def getConnection(userdn, username, password):
            server = ldap3.Server(
                self.server_address,
                port=self.server_port,
                use_ssl=self.use_ssl
            )
            self.log.debug('Attempting to bind {username} with {userdn}'.format(
                    username=username,
                    userdn=userdn
            ))
            conn = ldap3.Connection(server, user=userdn, password=password)
            return conn
        
        # Protect against invalid usernames as well as LDAP injection attacks
        if not re.match(self.valid_username_regex, username):
            self.log.warn('username:%s Illegal characters in username, must match regex %s', username, self.valid_username_regex)
            return None

        # No empty passwords!
        if password is None or password.strip() == '':
            self.log.warn('username:%s Login denied for blank password', username)
            return None
        
        isBound = False
        self.log.debug("TYPE= '%s'",isinstance(self.bind_dn_template, list))
        # In case, there are multiple binding templates
        if isinstance(self.bind_dn_template, list):
            for dn in self.bind_dn_template:
                userdn = dn.format(username=username)
                conn = getConnection(userdn, username, password)
                isBound = conn.bind()
                self.log.debug('Status of user bind {username} with {userdn} : {isBound}'.format(
                    username=username,
                    userdn=userdn,
                    isBound=isBound
                ))                
                if isBound:
                    break
        else:
            userdn = self.bind_dn_template.format(username=username)
            conn = getConnection(userdn, username, password)
            isBound = conn.bind()

        if isBound:
            if self.allowed_groups:
                if self.lookup_dn:
                    # In some cases, like AD, we don't bind with the DN, and need to discover it.
                    conn.search(
                        search_base=self.user_search_base,
                        search_scope=ldap3.SUBTREE,
                        search_filter='({userattr}={username})'.format(
                            userattr=self.user_attribute,
                            username=username
                        ),
                        attributes=[self.user_attribute]
                    )

                    if len(conn.response) == 0:
                        self.log.warn('username:%s No such user entry found when looking up with attribute %s', username, self.user_attribute)
                        return None
                    userdn = conn.response[0]['dn']

                self.log.debug('username:%s Using dn %s', username, userdn)
                for group in self.allowed_groups:
                    groupfilter = (
                        '(|'
                        '(member={userdn})'
                        '(uniqueMember={userdn})'
                        '(memberUid={uid})'
                        ')'
                    ).format(userdn=userdn, uid=username)
                    groupattributes = ['member', 'uniqueMember', 'memberUid']
                    if conn.search(
                        group,
                        search_scope=ldap3.BASE,
                        search_filter=groupfilter,
                        attributes=groupattributes
                    ):
                        # Pam authentiacation with Kerberos
                        try:
                            pamela.authenticate(username, password, service=self.service, resetcred=pamela.PAM_ESTABLISH_CRED)
                        except pamela.PAMError as e:
                            if handler is not None:
                                self.log.warning("PAM Authentication failed (%s@%s): %s", username, handler.request.remote_ip, e)
                            else:
                                self.log.warning("PAM Authentication failed: %s", e)
                            return None
                        else:
                            return username
                # If we reach here, then none of the groups matched
                self.log.warn('username:%s User not in any of the allowed groups', username)
                return None
            else:
                # Pam authentiacation with Kerberos
                try:
                    pamela.authenticate(username, password, service=self.service, resetcred=pamela.PAM_ESTABLISH_CRED)
                except pamela.PAMError as e:
                    if handler is not None:
                        self.log.warning("PAM Authentication failed (%s@%s): %s", username, handler.request.remote_ip, e)
                    else:
                        self.log.warning("PAM Authentication failed: %s", e)
                    return None
                else:
                    return username
        else:
            self.log.warn('Invalid password for user {username}'.format(
                username=userdn,
            ))
            return None


c.JupyterHub.authenticator_class = KerberosPAMwithLDAPAuthenticator

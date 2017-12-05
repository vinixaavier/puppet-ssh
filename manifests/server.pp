# ssh::server
#
# This is a public and main class to install and configure sshd, 
# which includes all other classes.
#
# @summary Allows you to configure all package options, 
# configuration file, and SSH server service. 
#
# @example
#   include ssh::server
#
#   or
#
#   class { 'ssh:server':
#     permitrootlogin => 'yes',
#     passwordauth    => 'yes',
#   }
#
# @param acceptenvs [Optional[Array]]
#   Specifies what environment variables sent by the client will be copied into the session's. 
#   Default value:   
#     - 'LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES'
#     - 'LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT'
#     - 'LC_IDENTIFICATION LC_ALL LANGUAGE'
#     - 'XMODIFIERS'
#
# @param addressfamily   [Optional[Enum['inet', 'inet6', 'any']]]
#   Specifies which address family should be used by sshd. Default value: undef.
#
# @param allowagentforwarding [Optional[Enum['yes', 'no']]]
#   Specifies whether ssh-agent forwarding is permitted. Default value: undef.
#
# @param allowgroups [Optional[String]]
#   This keyword can be followed by a list of group name patterns, separated by spaces. Default value: undef.
#
# @param allowstreamlocalforwarding [Optional[Enum['yes', 'no', 'all', 'local', 'remote']]]
#   Specifies whether StreamLocal (Unix-domain socket) forwarding is permitted. Default value: undef.
#
# @param allowtcpforwarding [Optional[Enum['yes', 'no', 'all', 'local', 'remote']]]
#   Specifies whether TCP forwarding is permitted. Default value: undef.
#
# @param allowusers [Optional[String]]
#   This keyword can be followed by a list of user name patterns, separated by spaces. Default value: undef.
#
# @param authmethods [Optional[String]]
#   Specifies the authentication methods that must be successfully completed 
#   for a user to be granted access. Default value: undef.
#
# @param authkeyscommand [Optional[String]]
#   Specifies a program to be used to look up the user's public keys. Default value: undef.
#
# @param authkeyscommanduser [Optional[String]]
#   Specifies the user under whose account the AuthorizedKeysCommand is run. Default value: undef.
#
# @param authkeysfile [Optional[String]]
#   Specifies the file that contains the public keys used for user 
#   authentication. Default value: '.ssh/authorized_keys'.
#
# @param authprincipalscommand [Optional[String]]
#   Specifies a program to be used to generate the list of allowed 
#   certificate principals as per AuthorizedPrincipalsFile. Default value: undef.
#
# @param authprincipalscommanduser [Optional[String]]
#   Specifies the user under whose account the AuthorizedPrincipalsCommand is run. Default value: undef.
#
# @param authprincipalsfile [Optional[String]]
#   Specifies a file that lists principal names that are accepted for 
#   certificate authentication. Default value: undef.
#
# @param banner [Optional[String]]
#   The contents of the specified file are sent to the remote user before 
#   authentication is allowed. Default value: undef.
#
# @param challengeresponseauth [Optional[Enum['yes', 'no']]]
#   Specifies whether challenge-response authentication is allowed. Default value: 'no'.
#
# @param chrootdirectory [Optional[String]]
#   Specifies the pathname of a directory to chroot to after authentication. Default value: undef.
#
# @param ciphers [Optional[String]]
#   Specifies the ciphers allowed. Default value: undef.
#
# @param clientalivecountmax [Optional[Integer]]
#   Sets the number of client alive messages which may be sent without 
#   sshd receiving any messages back from the client. Default value: undef.
#
# @param clientaliveinterval [Optional[Integer]]
#   Sets a timeout interval in seconds after which if no data has been 
#   received from the client, sshd. Default value: undef.
#
# @param compression [Optional[String]]
#   Specifies whether compression is enabled after the user has authenticated 
#   successfully. Default value: undef.
#
# @param conf_dir [Stdlib::Absolutepath]
#   Specifies the configuration directory of SSH Server. Default value: '/etc/ssh'.
#
# @param conf_dir_mode [Stdlib::Filemode]
#   Specifies the configuration directory permissions in octal format. Default value: '0755'.
#
# @param conf_file [Stdlib::Absolutepath]
#   Specifies the configuration file of SSH Server. Default value: '/etc/ssh/sshd_config'.
#
# @param conf_file_mode [Stdlib::Filemode]
#   Specifies the configuration file permissions in octal format. Default value: '0644'.
#
# @param conf_group [Variant[String, Integer]]
#   Specifies the group owner of the configuration file and directory. Default value: '0' or 'root'.
#
# @param conf_owner [Variant[String, Integer]]
#   Specifies the owner of the configuration file and directory. Default value: '0' or 'root'.
#
# @param denygroups [Optional[String]]
#   This keyword can be followed by a list of group name patterns, separated by spaces. Default value: undef.
#
# @param denyusers [Optional[String]]
#   This keyword can be followed by a list of user name patterns, separated by spaces. Default value: undef.
#
# @param disableforwarding [Optional[String]]
#   Disables all forwarding features, including X11, ssh-agent, TCP and StreamLocal. Default value: undef.
#
# @param exposeauthinfo [Optional[Enum['yes', 'no']]]
#   Writes a temporary file containing a list of authentication methods 
#   and public credentials (e.g. keys) used to authenticate the user. Default value: undef.
#
# @param fingerprinthash [Optional[Enum['md5', 'sha256']]]
#   Specifies the hash algorithm used when logging key fingerprints. Default value: undef.
#
# @param forcecommand [Optional[String]]
#   Forces the execution of the command specified by ForceCommand, ignoring any 
#   command supplied by the client and ~/.ssh/rc if present. Default value: undef.
#
# @param gatewayports [Optional[Enum['yes', 'no', 'clientspecified']]]
#   Specifies whether remote hosts are allowed to connect to ports forwarded 
#   for the client. Default value: undef.
#
# @param gssapiauth [Optional[Enum['yes', 'no']]]
#   Specifies whether user authentication based on GSSAPI is allowed. Default value: 'yes'.
#
# @param gssapicleanupcredentials [Optional[Enum['yes', 'no']]]
#   Specifies whether to automatically destroy the user's credentials cache on logout. Default value: 'no'.
#
# @param gssapienablek5users [Optional[Enum['yes', 'no']]]
#   Specifies if k5users should be enable. Default value: undef.
#
# @param gssapikeyexchange [Optional[Enum['yes', 'no']]]
#   Specifies if will have GSSAPI key exchange. Default value: undef.
#
# @param gssapistrictacceptorcheck [Optional[Enum['yes', 'no']]]
#   Determines whether to be strict about the identity of the GSSAPI acceptor 
#   a client authenticates against. Default value: undef.
#
# @param hostbasedacceptedkeytypes [Optional[String]]
#   Specifies the key types that will be accepted for hostbased authentication 
#   as a comma-separated pattern list. Default value: undef.
#
# @param hostbasedauth [Optional[Enum['yes', 'no']]]
#   Specifies whether rhosts or /etc/hosts.equiv authentication together with 
#   successful public key client host authentication is allowed (host-based authentication). Default value: 'no'.
#
# @param hostbasedusesnamefrompacketonly [Optional[Enum['yes', 'no']]]
#   Specifies whether or not the server will attempt to perform a reverse 
#   name lookup when matching the name in the ~/.shosts, ~/.rhosts, and /etc/hosts.equiv files 
#   during HostbasedAuthentication. Default value: undef.
#
# @param hostcertificate [Optional[String]]
#   Specifies a file containing a public host certificate. Default value: undef.
#
# @param hostkeys [Optional[Array[Stdlib::Absolutepath]]]
#   Specifies a file containing a private host key used by SSH. 
#   Default value:
#     - '/etc/ssh/ssh_host_rsa_key'
#     - '/etc/ssh/ssh_host_ecdsa_key'
#     - '/etc/ssh/ssh_host_ed25519_key'
#     - '/etc/ssh/ssh_host_dsa_key'
#
# @param hostkeyagent [Optional[String]]
#   Identifies the UNIX-domain socket used to communicate with an agent that 
#   has access to the private host keys. Default value: undef.
#
# @param hostkeyalgorithms [Optional[String]]
#   Specifies the host key algorithms that the server offers. Default value: undef.
#
# @param ignorerhosts [Optional[Enum['yes', 'no']]]
#   Specifies that .rhosts and .shosts files will not be used in HostbasedAuthentication. Default value: undef.
#
# @param ignoreuserknownhosts [Optional[Enum['yes', 'no']]]
#   Specifies whether sshd should ignore the user's ~/.ssh/known_hosts during 
#   HostbasedAuthentication. Default value: undef.
#
# @param ipqos [Optional[String]]
#   Specifies the IPv4 type-of-service or DSCP class for the connection. Default value: undef.
#
# @param kbdinteractiveauth [Optional[Enum['yes', 'no']]]
#   Specifies whether to allow keyboard-interactive authentication. Default value: undef.
#
# @param krbsauth [Optional[Enum['yes', 'no']]]
#   Specifies whether the password provided by the user for PasswordAuthentication 
#   will be validated through the Kerberos KDC. Default value: undef.
#
# @param krbsgetafstoken [Optional[Enum['yes', 'no']]]
#   If AFS is active and the user has a Kerberos 5 TGT, attempt to acquire an AFS 
#   token before accessing the user's home directory. Default value: undef.
#
# @param krbsorlocalpasswd [Optional[Enum['yes', 'no']]]
#   If password authentication through Kerberos fails then the password will be 
#   validated via any additional local mechanism such as /etc/passwd. Default value: undef.
#
# @param krbsticketcleanup [Optional[Enum['yes', 'no']]]
#   Specifies whether to automatically destroy the user's ticket cache file 
#   on logout. Default value: undef.
#
# @param krbsusekuserok [Optional[Enum['yes', 'no']]]
#   Specifies if kerberos kuserok should be used. Default value: undef.
#
# @param kexalgorithms [Optional[String]]
#   Specifies the available KEX (Key Exchange) algorithms. Default value: undef.
#
# @param keyregenerationinterval [Optional[Integer]]]
#   Specifies interval of regeneration key. Default value: 3600.
#
# @param listenaddress [Optional[String]]
#   Specifies the local addresses sshd should listen on. Default value: undef.
#
# @param logingracetime [Optional[Integer]]]
#   The server disconnects after this time if the user has not successfully logged in. Default value: 120.
#
# @param log_level [Optional[Pattern[/.*[A-Z]/]]]
#   Gives the verbosity level that is used when logging messages from sshd. Default value: 'INFO'.
#
# @param macs [Optional[String]]
#   Specifies the available MAC (message authentication code) algorithms. Default value: undef.
#
# @param maxauthtries [Optional[Integer]]]
#   Specifies the maximum number of authentication attempts permitted per connection. Default value: undef.
#
# @param maxsessions [Optional[Integer]]]
#   Specifies the maximum number of open shell, login or subsystem (e.g. sftp) 
#   sessions permitted per network connection. Default value: undef.
#
# @param maxstartups [Optional[String]]
#   Specifies the maximum number of concurrent unauthenticated connections 
#   to the SSH daemon. Default value: undef.
#
# @param package_name [String]
#   Specifies the package name. Default value: 'openssh-server'.
#
# @param package_ensure [Enum['latest', 'present', 'absent']]
#   Specifies if package should be installed. Default value: 'latest'.
#
# @param passwordauth [Optional[Enum['yes', 'no']]]
#   Specifies whether password authentication is allowed. Default value: 'yes'.
#
# @param permitemptypasswords [Optional[Enum['yes', 'no']]]
#   When password authentication is allowed, it specifies whether 
#   the server allows login to accounts with empty password strings. Default value: 'no'.
#
# @param permitopen [Optional[String]]
#   Specifies the destinations to which TCP port forwarding is permitted. Default value: undef.
#
# @param permitrootlogin [Optional[Enum['yes', 'no', 'prohibit-password', 'forced-commands-only']]]
#   Specifies whether root can log in using ssh. Default value: undef.
#
# @param permit_tty [Optional[Enum['yes', 'no']]]
#   Specifies whether pty allocation is permitted. Default value: undef.
#
# @param permit_tunnel [Optional[Enum['yes', 'no']]]
#   Specifies whether tun device forwarding is allowed. Default value: undef.
#
# @param permituserenvironment [Optional[Enum['yes', 'no']]]
#   Specifies whether ~/.ssh/environment and environment= options in ~/.ssh/authorized_keys 
#   are processed by sshd. Default value: undef.
#
# @param permituser_rc [Optional[Enum['yes', 'no']]]
#   Specifies whether any ~/.ssh/rc file is executed. Default value: undef.
#
# @param pidfile [Optional[Stdlib::Absolutepath]]
#   Specifies the file that contains the process ID of the SSH daemon, or 
#   none to not write one. Default value: undef.
#
# @param port [Optional[Integer[1,65535]]]
#   Specifies the port number that sshd listens on. Default value: undef.
#
# @param printlastlog [Optional[Enum['yes', 'no']]]
#   Specifies whether sshd(8) should print the date and time of the last 
#   user login when a user logs in interactively. Default value: 'yes'.
#
# @param printmotd [Optional[Enum['yes', 'no']]]
#   Specifies whether sshd should print /etc/motd when a user logs in interactively. Default value: 'no'.
#
# @param protocol [Optional[Integer]]]
#   Specifies protocol version. Default value: undef.
#
# @param pubkeyacceptedkeytypes [Optional[String]]
#   Specifies the key types that will be accepted for public key authentication 
#   as a comma-separated pattern list. Default value: undef.
#
# @param pubkeyauth [Optional[Enum['yes', 'no']]]
#   Specifies whether public key authentication is allowed. Default value: undef.
#
# @param rekeylimit [Optional[String]]
#   Specifies the maximum amount of data that may be transmitted before the 
#   session key is renegotiated, optionally followed a maximum amount of time that 
#   may pass before the session key is renegotiated. Default value: undef.
#
# @param revokedkeys [Optional[String]]
#   Specifies revoked public keys file, or none to not use one. Keys listed in this 
#   file will be refused for public key authentication. Default value: undef.
#
# @param rdomain [Optional[String]]
#   Specifies an explicit routing domain that is applied after 
#   authentication has completed. Default value: undef.
#
# @param rhostsrsa_auth [Optional[Enum['yes', 'no']]]
#   Specifies if RHosts RSA authentication should be enabled. Default value: 'yes'.
#
# @param serverkeybits [Optional[Integer]]]
#   Specifies amount bits of server key. Default value: 1024.
#
# @param service_enable [Boolean]
#   Specifies if service should be started at boot. Default value: 'true'.
#
# @param service_ensure [Stdlib::Ensure::Service]
#   Specifies if service should be running or stopped. Default value: 'running'.
#
# @param service_name [String]
#   Specifies the service name. Default value: Debian-like 'ssh' or RedHat-like 'sshd'.
#
# @param showpatchlevel [Optional[Enum['yes', 'no']]]
#   Specifies if should be show patch level. Default value: undef.
#
# @param streamlocalbindmask [Optional[Stdlib::Filemode]]
#   Sets the octal file creation mode mask (umask) used when creating a 
#   Unix-domain socket file for local or remote port forwarding. Default value: undef.
#
# @param streamlocalbindunlink [Optional[Enum['yes', 'no']]]
#   Specifies whether to remove an existing Unix-domain socket file for 
#   local or remote port forwarding before creating a new one. Default value: undef.
#
# @param strictmodes [Optional[Enum['yes', 'no']]]
#   Specifies whether sshd should check file modes and ownership 
#   of the user's files and home directory before accepting login. Default value: 'yes'.
#
# @param subsystem [Optional[String]]
#   Configures an external subsystem (e.g. file transfer daemon). 
#   Default value: undef.
#
# @param syslogfacility [Optional[Pattern[/.*[A-Z]/]]]
#   Gives the facility code that is used when logging messages from sshd. Default value: 'AUTHPRIV'.
#
# @param tcpkeepalive [Optional[Enum['yes', 'no']]]
#   Specifies whether the system should send TCP keepalive messages to 
#   the other side. If they are sent, death of the connection or crash of 
#   one of the machines will be properly noticed. Default value: 'yes'.
#
# @param trustedusercakeys [Optional[String]]
#   Specifies a file containing public keys of certificate authorities 
#   that are trusted to sign user certificates for authentication, or none to not use one. Default value: undef.
#
# @param usedns [Optional[Enum['yes', 'no']]]
#   Specifies whether sshd should look up the remote host name, 
#   and to check that the resolved host name for the remote IP address 
#   maps back to the very same IP address. Default value: 'no'.
#
# @param uselogin [Optional[Enum['yes', 'no']]]
#   Specifies wheter sshd use login. Default value: undef.
#
# @param usepam [Optional[Enum['yes', 'no']]]
#   Specifies wheter sshd use PAM. Default value: 'yes'.
#
# @param useprivilegeseparation [Optional[String]]
#   Specifies wheter sshd use privilege separation. Default value: 'yes'.
#
# @param versionaddendum [Optional[String]]
#   Optionally specifies additional text to append to the SSH protocol 
#   banner sent by the server upon connection. Default value: undef.
#
# @param x11displayoffset [Optional[Integer]]]
#   Specifies the first display number available for sshd's X11 forwarding. Default value: 10.
#
# @param x11forwarding [Optional[Enum['yes', 'no']]]
#   Specifies whether X11 forwarding is permitted. Default value: 'yes'.
#
# @param x11uselocalhost [Optional[Enum['yes', 'no']]]
#   Specifies whether sshd should bind the X11 forwarding server to the 
#   loopback address or to the wildcard address. Default value: undef.
#
# @param xauthlocation [Optional[Stdlib::Absolutepath]]
#   Specifies the full pathname of the xauth. Default value: undef.
#
class ssh::server (

  Optional[Array]                                                          $acceptenvs,
  Optional[Enum['inet', 'inet6', 'any']]                                   $addressfamily,
  Optional[Enum['yes', 'no']]                                              $allowagentforwarding,
  Optional[String]                                                         $allowgroups,
  Optional[Enum['yes', 'no', 'all', 'local', 'remote']]                    $allowtcpforwarding,
  Optional[Enum['yes', 'no', 'all', 'local', 'remote']]                    $allowstreamlocalforwarding,
  Optional[String]                                                         $allowusers,
  Optional[String]                                                         $authmethods,
  Optional[String]                                                         $authkeyscommand,
  Optional[String]                                                         $authkeyscommanduser,
  Optional[String]                                                         $authkeysfile,
  Optional[String]                                                         $authprincipalscommand,
  Optional[String]                                                         $authprincipalscommanduser,
  Optional[String]                                                         $authprincipalsfile,
  Optional[String]                                                         $banner,
  Optional[Enum['yes', 'no']]                                              $challengeresponseauth,
  Optional[String]                                                         $chrootdirectory,
  Optional[String]                                                         $ciphers,
  Optional[Integer]                                                        $clientalivecountmax,
  Optional[Integer]                                                        $clientaliveinterval,
  Optional[String]                                                         $compression,
  Stdlib::Absolutepath                                                     $conf_dir,
  Stdlib::Filemode                                                         $conf_dir_mode,
  Stdlib::Absolutepath                                                     $conf_file,
  Stdlib::Filemode                                                         $conf_file_mode,
  Variant[String, Integer]                                                 $conf_group,
  Variant[String, Integer]                                                 $conf_owner,
  Optional[String]                                                         $denygroups,
  Optional[String]                                                         $denyusers,
  Optional[String]                                                         $disableforwarding,
  Optional[Enum['yes', 'no']]                                              $exposeauthinfo,
  Optional[Enum['md5', 'sha256']]                                          $fingerprinthash,
  Optional[String]                                                         $forcecommand,
  Optional[Enum['yes', 'no', 'clientspecified']]                           $gatewayports,
  Optional[Enum['yes', 'no']]                                              $gssapiauth,
  Optional[Enum['yes', 'no']]                                              $gssapicleanupcredentials,
  Optional[Enum['yes', 'no']]                                              $gssapienablek5users,
  Optional[Enum['yes', 'no']]                                              $gssapikeyexchange,
  Optional[Enum['yes', 'no']]                                              $gssapistrictacceptorcheck,
  Optional[String]                                                         $hostbasedacceptedkeytypes,
  Optional[Enum['yes', 'no']]                                              $hostbasedauth,
  Optional[Enum['yes', 'no']]                                              $hostbasedusesnamefrompacketonly,
  Optional[String]                                                         $hostcertificate,
  Optional[Array[Stdlib::Absolutepath]]                                    $hostkeys,
  Optional[String]                                                         $hostkeyagent,
  Optional[String]                                                         $hostkeyalgorithms,
  Optional[Enum['yes', 'no']]                                              $ignorerhosts,
  Optional[Enum['yes', 'no']]                                              $ignoreuserknownhosts,
  Optional[String]                                                         $ipqos,
  Optional[Enum['yes', 'no']]                                              $kbdinteractiveauth,
  Optional[Enum['yes', 'no']]                                              $krbsauth,
  Optional[Enum['yes', 'no']]                                              $krbsgetafstoken,
  Optional[Enum['yes', 'no']]                                              $krbsorlocalpasswd,
  Optional[Enum['yes', 'no']]                                              $krbsticketcleanup,
  Optional[Enum['yes', 'no']]                                              $krbsusekuserok,
  Optional[String]                                                         $kexalgorithms,
  Optional[Integer]                                                        $keyregenerationinterval,
  Optional[String]                                                         $listenaddress,
  Optional[Integer]                                                        $logingracetime,
  Optional[Pattern[/.*[A-Z]/]]                                             $log_level,
  Optional[String]                                                         $macs,
  # Optional[String]                                                       $match,
  Optional[Integer]                                                        $maxauthtries,
  Optional[Integer]                                                        $maxsessions,
  Optional[String]                                                         $maxstartups,
  String                                                                   $package_name,
  Enum['latest', 'present', 'absent']                                      $package_ensure,
  Optional[Enum['yes', 'no']]                                              $passwordauth,
  Optional[Enum['yes', 'no']]                                              $permitemptypasswords,
  Optional[String]                                                         $permitopen,
  Optional[Enum['yes', 'no', 'prohibit-password', 'forced-commands-only']] $permitrootlogin,
  Optional[Enum['yes', 'no']]                                              $permit_tty,
  Optional[Enum['yes', 'no']]                                              $permit_tunnel,
  Optional[Enum['yes', 'no']]                                              $permituserenvironment,
  Optional[Enum['yes', 'no']]                                              $permituser_rc,
  Optional[Stdlib::Absolutepath]                                           $pidfile,
  Optional[Integer[1,65535]]                                               $port,
  Optional[Enum['yes', 'no']]                                              $printmotd,
  Optional[Enum['yes', 'no']]                                              $printlastlog,
  Optional[Integer]                                                        $protocol,
  Optional[String]                                                         $pubkeyacceptedkeytypes,
  Optional[Enum['yes', 'no']]                                              $pubkeyauth,
  Optional[String]                                                         $rekeylimit,
  Optional[String]                                                         $revokedkeys,
  Optional[String]                                                         $rdomain,
  Optional[Enum['yes', 'no']]                                              $rhostsrsa_auth,
  Optional[Integer]                                                        $serverkeybits,
  Boolean                                                                  $service_enable,
  Stdlib::Ensure::Service                                                  $service_ensure,
  String                                                                   $service_name,
  Optional[Enum['yes', 'no']]                                              $showpatchlevel,
  Optional[Stdlib::Filemode]                                               $streamlocalbindmask,
  Optional[Enum['yes', 'no']]                                              $streamlocalbindunlink,
  Optional[Enum['yes', 'no']]                                              $strictmodes,
  Optional[String]                                                         $subsystem,
  Optional[Pattern[/.*[A-Z]/]]                                             $syslogfacility,
  Optional[Enum['yes', 'no']]                                              $tcpkeepalive,
  Optional[String]                                                         $trustedusercakeys,
  Optional[Enum['yes', 'no']]                                              $usedns,
  Optional[Enum['yes', 'no']]                                              $uselogin,
  Optional[Enum['yes', 'no']]                                              $usepam,
  Optional[String]                                                         $useprivilegeseparation,
  Optional[String]                                                         $versionaddendum,
  Optional[Integer]                                                        $x11displayoffset,
  Optional[Enum['yes', 'no']]                                              $x11forwarding,
  Optional[Enum['yes', 'no']]                                              $x11uselocalhost,
  Optional[Stdlib::Absolutepath]                                           $xauthlocation,

) {

  contain ssh::server::install
  contain ssh::server::config
  contain ssh::server::service

  Class['ssh::server::install']
    -> Class['ssh::server::config']
      ~> Class['ssh::server::service']

}

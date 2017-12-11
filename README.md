
[![Build Status](https://travis-ci.org/vinixavier/puppet-ssh.svg?branch=master)](https://travis-ci.org/vinixavier/puppet-ssh)  ![License](https://img.shields.io/badge/license-Apache%202-blue.svg) ![Version](https://img.shields.io/puppetforge/v/viniciusxavier/ssh.svg) ![Downloads](https://img.shields.io/puppetforge/dt/viniciusxavier/ssh.svg)

# ssh

#### Table of Contents

1. [Description](#description)
2. [Setup - The basics of getting started with ssh](#setup)
    * [What ssh affects](#what-ssh-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with ssh](#beginning-with-ssh)
3. [Usage - Configuration options and additional functionality](#usage)
4. [Reference - An under-the-hood peek at what the module is doing and how](#reference)
5. [Limitations - OS compatibility, etc.](#limitations)
6. [Development - Guide for contributing to the module](#development)

## Description

The ssh module installs, configures, and manages the SSH Server service and SSH Client across a range of operating systems and distributions.

## Setup

### What ssh affects **OPTIONAL**

* Package, configuration file and service.
* Listened ports

### Setup Requirements

* Puppet >= 4.10
* Facter >= 2.0
* [Stdlib Module](https://github.com/puppetlabs/puppetlabs-stdlib)

### Beginning with ssh

`include ::ssh::server` is enough to get you up and running with default parameters.
You can pass the parameters which if permit root login, allow password authentication and public key authentication, like this:

```puppet
class { '::ssh::server':
  permitrootlogin => 'yes',
  pubkeyauth      => 'yes',
  passwordauth    => 'yes',
}
```

## Usage

All parameters for the ssh module are contained within the main class to SSH Server and main class to SSH Client.
Set the options you want and see the common usages below for examples.

### Install ssh server and enable with default parameters

```puppet
include ::ssh::server
```


### Change port, allow ipv6 and set listen address

```puppet
class { '::ssh::server':
  port            => 5000,
  addressfamily   => 'inet6',
  listenaddress   => '192.168.200.10',
}
```

### Disable DNS resolution, set banner file path and allow which groups can access server

```puppet
class { '::ssh::server':
  usedns      => 'no',
  banner      => '/etc/default/banner',
  allowgroups => ['sysadmins', 'engineers'],
}
```

## Reference

### Classes

#### Public Classes

* ssh::server: Main class, includes all other classes.

#### Private Classes

* ssh::server::install: Handles the packages.
* ssh::server::config:  Handles the configuration file.
* ssh::server::service: Handles the service.

### Parameters

The following parameters are available in the `ssh::server` class:

#### `acceptenvs`

Optional.

Data type: Array.

Specifies what environment variables sent by the client will be copied into the session's.

Default value:

* 'LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES'
* 'LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT'
* 'LC_IDENTIFICATION LC_ALL LANGUAGE'
* 'XMODIFIERS'

#### `addressfamily`

Optional.

Data type: Enum['inet', 'inet6', 'any'].

Specifies which address family should be used by sshd.

Default value: undef.

#### `allowagentforwarding`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether ssh-agent forwarding is permitted.

Default value: undef.

#### `allowgroups`

Optional.

Data type: String.

This keyword can be followed by a list of group name patterns, separated by spaces. Default value: undef.

#### `allowstreamlocalforwarding`

Optional.

Data type: Enum['yes', 'no', 'all', 'local', 'remote'].

Specifies whether StreamLocal (Unix-domain socket) forwarding is permitted.

Default value: undef.

##### `allowtcpforwarding`

Optional.

Data type: Enum['yes', 'no', 'all', 'local', 'remote'].

Specifies whether TCP forwarding is permitted.

Default value: undef.

##### `allowusers`

Optional.

Data type: String.

This keyword can be followed by a list of user name patterns, separated by spaces.

Default value: undef.

#### `authmethods`

Optional.

Data type: String.

Specifies the authentication methods that must be successfully completed for a user to be granted access.

Default value: undef.

#### `authkeyscommand`

Optional.

Data type: String.

Specifies a program to be used to look up the user's public keys.

Default value: undef.

#### `authkeyscommanduser`

Optional.

Data type: String.

Specifies the user under whose account the AuthorizedKeysCommand is run.

Default value: undef.

#### `authkeysfile`

Optional.

Data type: String.

Specifies the file that contains the public keys used for user authentication.

Default value: '.ssh/authorized_keys'.

#### `authprincipalscommand`

Optional.

Data type: String.

Specifies a program to be used to generate the list of allowed certificate principals as per AuthorizedPrincipalsFile.

Default value: undef.

#### `authprincipalscommanduser`

Optional.

Data type: String.

Specifies the user under whose account the AuthorizedPrincipalsCommand is run.

Default value: undef.

#### `authprincipalsfile`

Optional.

Data type: String.

Specifies a file that lists principal names that are accepted for certificate authentication.

Default value: undef.

#### `banner`

Optional.

Data type: String.

The contents of the specified file are sent to the remote user before authentication is allowed.

Default value: undef.

#### `challengeresponseauth`

Optional

Data type: Enum['yes', 'no'].

Specifies whether challenge-response authentication is allowed. 

Default value: 'no'.

#### `chrootdirectory`

Optional

Data type: String.

Specifies the pathname of a directory to chroot to after authentication.

Default value: undef.

#### `ciphers`

Optional.

Data type: String.

Specifies the ciphers allowed.

Default value: undef.

#### `clientalivecountmax`

Optional

Data type: Integer.

Sets the number of client alive messages which may be sent without sshd receiving any messages back from the client.

Default value: undef.

#### `clientaliveinterval`

Optional

Data type: Integer.

Sets a timeout interval in seconds after which if no data has been received from the client, sshd.

Default value: undef.

#### `compression`

Optional.

Data type: String.

Specifies whether compression is enabled after the user has authenticated successfully.

Default value: undef.

#### `conf_dir`

Data type: Stdlib::Absolutepath.

Specifies the configuration directory of SSH Server.

Default value: '/etc/ssh'.

#### `conf_dir_mode`

Data type: Stdlib::Filemode.

Specifies the configuration directory permissions in octal format.

Default value: '0755'.

#### `conf_file`

Data type: Stdlib::Absolutepath.

Specifies the configuration file of SSH Server.

Default value: '/etc/ssh/sshd_config'.

#### `conf_file_mode`

Data type: Stdlib::Filemode.

Specifies the configuration file permissions in octal format. Default value: '0644'.

#### `conf_group`

Data type: Variant[String, Integer]

Specifies the group owner of the configuration file and directory.

Default value: '0' or 'root'.

#### `conf_owner`

Data type: Variant[String, Integer].

Specifies the owner of the configuration file and directory.

Default value: '0' or 'root'.

#### `denygroups`

Optional.

Data type: String.

This keyword can be followed by a list of group name patterns, separated by spaces.

Default value: undef.

#### `denyusers`

Optional.

Data type: String.

This keyword can be followed by a list of user name patterns, separated by spaces. 

Default value: undef.

#### `disableforwarding`

Optional

Data type: String.

Disables all forwarding features, including X11, ssh-agent, TCP and StreamLocal.

Default value: undef.

#### `exposeauthinfo`

Optional.

Data type: Enum['yes', 'no']

Writes a temporary file containing a list of authentication methods and public credentials (e.g. keys) used to authenticate the user.

Default value: undef.

#### `fingerprinthash`

Optional.

Data type: Enum['md5', 'sha256'].

Specifies the hash algorithm used when logging key fingerprints.

Default value: undef.

#### `forcecommand`

Optional.

Data type: String.

Forces the execution of the command specified by ForceCommand, ignoring any command supplied by the client and ~/.ssh/rc if present.

Default value: undef.

#### `gatewayports`

Optional.

Data type: Enum['yes', 'no', 'clientspecified']

Specifies whether remote hosts are allowed to connect to ports forwarded for the client.

Default value: undef.

#### `gssapiauth`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether user authentication based on GSSAPI is allowed.

Default value: 'yes'.

#### `gssapicleanupcredentials`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether to automatically destroy the user's credentials cache on logout.

Default value: 'no'.

#### `gssapienablek5users`

Optional

Data type: Enum['yes', 'no']

Specifies if k5users should be enable.

Default value: undef.

#### `gssapikeyexchange`

Optional

Data type: Enum['yes', 'no']

Specifies if will have GSSAPI key exchange. Default value: undef.

#### `gssapistrictacceptorcheck`

Optional.

Data type: Enum['yes', 'no'].

Determines whether to be strict about the identity of the GSSAPI acceptor a client authenticates against.

Default value: undef.

#### `hostbasedacceptedkeytypes`

Optional.

Data type: String.

Specifies the key types that will be accepted for hostbased authentication
as a comma-separated pattern list.

Default value: undef.

#### `hostbasedauth`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether rhosts or /etc/hosts.equiv authentication together with successful public key client host authentication is allowed (host-based authentication).

Default value: 'no'.

#### `hostbasedusesnamefrompacketonly`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether or not the server will attempt to perform a reverse name lookup when matching the name in the ~/.shosts, ~/.rhosts, and /etc/hosts.equiv files during HostbasedAuthentication.

Default value: undef.

#### `hostcertificate`

Optional.

Data type: String.

Specifies a file containing a public host certificate.

Default value: undef.

#### `hostkeys`

Optional.

Data type: Array[Stdlib::Absolutepath].

Specifies a file containing a private host key used by SSH.

Default value:

* '/etc/ssh/ssh_host_rsa_key'
* '/etc/ssh/ssh_host_ecdsa_key'
* '/etc/ssh/ssh_host_ed25519_key'
* '/etc/ssh/ssh_host_dsa_key'

#### `hostkeyagent`

Optional.

Data type: String.

Identifies the UNIX-domain socket used to communicate with an agent that has access to the private host keys. Default value: undef.

#### `hostkeyalgorithms`

Optional.

Data type: String.

Specifies the host key algorithms that the server offers.

Default value: undef.

#### `ignorerhosts`

Optional.

Data type: Enum['yes', 'no'].

Specifies that .rhosts and .shosts files will not be used in HostbasedAuthentication.

Default value: undef.

#### `ignoreuserknownhosts`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether sshd should ignore the user's ~/.ssh/known_hosts during HostbasedAuthentication.

Default value: undef.

#### `ipqos`

Optional.

Data type: String.

Specifies the IPv4 type-of-service or DSCP class for the connection.

Default value: undef.

#### `kbdinteractiveauth`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether to allow keyboard-interactive authentication.

Default value: undef.

#### `krbsauth`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether the password provided by the user for PasswordAuthentication
will be validated through the Kerberos KDC.

Default value: undef.

#### `krbsgetafstoken`

Optional.

Data type: Enum['yes', 'no'].

If AFS is active and the user has a Kerberos 5 TGT, attempt to acquire an AFS token before accessing the user's home directory.

Default value: undef.

#### `krbsorlocalpasswd`

Optional.

Data type: Enum['yes', 'no'].

If password authentication through Kerberos fails then the password will be validated via any additional local mechanism such as /etc/passwd.

Default value: undef.

#### `krbsticketcleanup`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether to automatically destroy the user's ticket cache file on logout.

Default value: undef.

#### `krbsusekuserok`

Optional.

Data type: Enum['yes', 'no'].

Specifies if kerberos kuserok should be used.

Default value: undef.

#### `kexalgorithms`

Optional.

Data type: String.

Specifies the available KEX (Key Exchange) algorithms.

Default value: undef.

#### `keyregenerationinterval`

Optional.

Data type: Integer.

Specifies interval of regeneration key.

Default value: 3600.

#### `listenaddress`

Optional.

Data type: String.

Specifies the local addresses sshd should listen on.

Default value: undef.

#### `logingracetime`

Optional.

Data type: Integer.

The server disconnects after this time if the user has not successfully logged in.

Default value: 120.

#### `log_level`

Optional.

Data type: Pattern[/.*[A-Z]/].

Gives the verbosity level that is used when logging messages from sshd.

Default value: 'INFO'.

#### `macs`

Optional.

Data type: String.

Specifies the available MAC (message authentication code) algorithms.

Default value: undef.

#### `maxauthtries`

Optional.

Data type: Integer.

Specifies the maximum number of authentication attempts permitted per connection.

Default value: undef.

#### `maxsessions`

Optional.

Data type: Integer.

Specifies the maximum number of open shell, login or subsystem (e.g. sftp) sessions permitted per network connection.

Default value: undef.

#### `maxstartups`

Optional.

Data type: String.

Specifies the maximum number of concurrent unauthenticated connections to the SSH daemon.

Default value: undef.

#### `package_name`

Data type: String.

Specifies the package name.

Default value: 'openssh-server'.

#### `package_ensure`

Data type: Enum['latest', 'present', 'absent']

Specifies if package should be installed.

Default value: 'latest'.

#### `passwordauth`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether password authentication is allowed.

Default value: 'yes'.

#### `permitemptypasswords`

Optional.

Data type: Enum['yes', 'no'].

When password authentication is allowed, it specifies whether the server allows login to accounts with empty password strings.

Default value: 'no'.

#### `permitopen`

Optional.

Data type: String.

Specifies the destinations to which TCP port forwarding is permitted.

Default value: undef.

#### `permitrootlogin`

Optional.

Data type: Enum['yes', 'no', 'prohibit-password', 'forced-commands-only'].

Specifies whether root can log in using ssh. 

Default value: undef.

#### `permit_tty`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether pty allocation is permitted.

Default value: undef.

#### `permit_tunnel`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether tun device forwarding is allowed.

Default value: undef.

#### `permituserenvironment`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether ~/.ssh/environment and environment= options in ~/.ssh/authorized_keys are processed by sshd.

Default value: undef.

#### `permituser_rc`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether any ~/.ssh/rc file is executed.

Default value: undef.

#### `pidfile`

Optional.

Data type: Stdlib::Absolutepath.

Specifies the file that contains the process ID of the SSH daemon, or none to not write one.

Default value: undef.

#### `port`

Optional.

Data type: Integer[1, 65535].

Specifies the port number that sshd listens on.

Default value: undef.

#### `printlastlog`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether sshd(8) should print the date and time of the last user login when a user logs in interactively.

Default value: 'yes'.

#### `printmotd`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether sshd should print /etc/motd when a user logs in interactively. 

Default value: 'no'.

#### `protocol`

Optional.

Data type: Integer.

Specifies protocol version.

Default value: undef.

#### `pubkeyacceptedkeytypes`

Optional.

Data type: String.

Specifies the key types that will be accepted for public key authentication as a comma-separated pattern list.

Default value: undef.

#### `pubkeyauth`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether public key authentication is allowed.

Default value: undef.

#### `rekeylimit`

Optional.

Data type: String.

Specifies the maximum amount of data that may be transmitted before the session key is renegotiated, optionally followed a maximum amount of time that may pass before the session key is renegotiated.

Default value: undef.

#### `revokedkeys`

Optional.

Data type: String.

Specifies revoked public keys file, or none to not use one. Keys listed in this file will be refused for public key authentication.

Default value: undef.

#### `rdomain`

Optional.

Data type: String.

Specifies an explicit routing domain that is applied after authentication has completed. 

Default value: undef.

#### `rhostsrsa_auth`

Optional.

Data type: Enum['yes', 'no'].

Specifies if RHosts RSA authentication should be enabled.

Default value: 'yes'.

#### `serverkeybits`

Optional.

Data type: Integer.

Specifies amount bits of server key.

Default value: 1024.

#### `service_enable`

Boolean.

Specifies if service should be started at boot.

Default value: 'true'.

#### `service_ensure`

Data type: Stdlib::Ensure::Service.

Specifies if service should be running or stopped.

Default value: 'running'.

#### `service_name`

Data type: String.

Specifies the service name.

Default value: Debian-like 'ssh' or RedHat-like 'sshd'.

#### `showpatchlevel`

Optional.

Data type: Enum['yes', 'no'].

Specifies if should be show patch level.

Default value: undef.

#### `streamlocalbindmask`

Optional.

Data type: Stdlib::Filemode.

Sets the octal file creation mode mask (umask) used when creating a Unix-domain socket file for local or remote port forwarding.

Default value: undef.

#### `streamlocalbindunlink`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether to remove an existing Unix-domain socket file for local or remote port forwarding before creating a new one.

Default value: undef.

#### `strictmodes`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether sshd should check file modes and ownership
of the user's files and home directory before accepting login.

Default value: 'yes'.

#### `subsystem`

Optional.

Data type: String.

Configures an external subsystem (e.g. file transfer daemon).

Default value: undef.

#### `syslogfacility`

Optional.

Data type: Pattern[/.*[A-Z]/].

Gives the facility code that is used when logging messages from sshd.

Default value: 'AUTHPRIV'.

#### `tcpkeepalive`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether the system should send TCP keepalive messages to the other side. If they are sent, death of the connection or crash of one of the machines will be properly noticed.

Default value: 'yes'.

#### `trustedusercakeys`

Optional.

Data type: String.

Specifies a file containing public keys of certificate authorities that are trusted to sign user certificates for authentication, or none to not use one. 

Default value: undef.

#### `usedns`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether sshd should look up the remote host name, and to check that the resolved host name for the remote IP address maps back to the very same IP address.

Default value: 'no'.

#### `uselogin`

Optional.

Data type: Enum['yes', 'no'].

Specifies wheter sshd use login.

Default value: undef.

#### `usepam`

Optional.

Data type: Enum['yes', 'no'].

Specifies wheter sshd use PAM.

Default value: 'yes'.

#### `useprivilegeseparation`

Optional.

Data type: String.

Specifies wheter sshd use privilege separation.

Default value: 'yes'.

#### `versionaddendum`

Optional.

Data type: String.

Optionally specifies additional text to append to the SSH protocol banner sent by the server upon connection. 

Default value: undef.

#### `x11displayoffset`

Optional.

Data type: Integer.

Specifies the first display number available for sshd's X11 forwarding.

Default value: 10.

#### `x11forwarding`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether X11 forwarding is permitted.

Default value: 'yes'.

#### `x11uselocalhost`

Optional.

Data type: Enum['yes', 'no'].

Specifies whether sshd should bind the X11 forwarding server to the loopback address or to the wildcard address.

Default value: undef.

#### `xauthlocation`

Optional.

Data type: Stdlib::Absolutepath.

Specifies the full pathname of the xauth.

Default value: undef.

## Limitations

This module has been tested on:

* Centos 7
* Ubuntu 16.04
* Debian 9
* Fedora 26
* Oracle Linux
* RedHat

## Development

Puppet modules on the Puppet Forge are open projects, and community contributions are essential for keeping them great. Please follow our guidelines when contributing changes.

For more information, see our [module contribution guide.](https://github.com/otherskins/puppet-ansible/blob/master/CONTRIBUTING.md)

## TODO

* Include ssh client management.
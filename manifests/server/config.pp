# ssh::server::config
#
# This is a private class to configure sshd_config file.
# Do not use directly.
#
# @summary Private class to manage configuration directory and files to SSH Server.
#
class ssh::server::config inherits ssh::server {

  file { $ssh::server::conf_dir:
    ensure => directory,
    owner  => $ssh::server::conf_owner,
    group  => $ssh::server::conf_group,
    mode   => $ssh::server::conf_dir_mode,
  }

  file { $ssh::server::conf_file:
    ensure  => present,
    owner   => $ssh::server::conf_owner,
    group   => $ssh::server::conf_group,
    mode    => $ssh::server::conf_file_mode,
    content => epp('ssh/sshd_config.epp'),
  }

}

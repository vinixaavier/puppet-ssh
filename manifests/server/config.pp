# ssh::server::config
#
# A description of what this class does
#
# @summary A short summary of the purpose of this class
#
# @example
#   include ssh::server::config
class ssh::server::config inherits ssh::server {

  file { $ssh::server::conf_dir:
    ensure => directory,
    owner  => $ssh::server::conf_owner,
    group  => $ssh::server::conf_group,
    mode   => $ssh::server::conf_dir_mode,
  }

  file { $ssh::server::conf_file:
    ensure => present,
    owner  => $ssh::server::conf_owner,
    group  => $ssh::server::conf_group,
    mode   => $ssh::server::conf_file_mode,
  }

}

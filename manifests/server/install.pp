# ssh::server::install
#
# This is a private class to install ssh packages.
# Do not use directly.
#
# @summary Private class to install SSH Server.
#
class ssh::server::install inherits ssh::server {

  package { $ssh::server::package_name:
    ensure => $ssh::server::package_ensure
  }

}

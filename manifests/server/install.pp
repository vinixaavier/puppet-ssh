# ssh::server::install
#
# A description of what this class does
#
# @summary A short summary of the purpose of this class
#
# @example
#   include ssh::server::install
class ssh::server::install inherits ssh::server {

  package { $ssh::server::package_name:
    ensure => $ssh::server::package_ensure
  }

}

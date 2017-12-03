# ssh::server::service
#
# A description of what this class does
#
# @summary A short summary of the purpose of this class
#
# @example
#   include ssh::server::service
class ssh::server::service inherits ssh::server {

  service { $ssh::server::service_name:
    ensure     => $ssh::server::service_ensure,
    enable     => $ssh::server::service_enable,
    hasstatus  => true,
    hasrestart => true,
  }

}

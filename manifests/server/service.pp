# ssh::server::service
#
# A description of what this class does
#
# @summary A short summary of the purpose of this class
#
# @example
#   include ssh::server::service
class ssh::server::service {

  service { $ssh::server::service_name:
    ensure     => $ssh::server::service_ensure,
    enable     => $ntp::server::service_enable,
    hasstatus  => true,
    hasrestart => true,
  }

}

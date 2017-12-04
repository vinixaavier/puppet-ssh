# ssh::server::service
#
# This is a private class to manage ssh service.
# Do not use directly.
#
# @summary Private class to manage SSH Server service.
#
class ssh::server::service inherits ssh::server {

  service { $ssh::server::service_name:
    ensure     => $ssh::server::service_ensure,
    enable     => $ssh::server::service_enable,
    hasstatus  => true,
    hasrestart => true,
  }

}

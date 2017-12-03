# ssh::server
#
# A description of what this class does
#
# @summary A short summary of the purpose of this class
#
# @example
#   include ssh::server
class ssh::server (

  String $package_name,
  String $package_ensure,
  String $conf_dir,
  String $conf_owner,
  String $conf_group,
  String $conf_dir_mode,
  String $conf_file_mode,
  String $service_name,
  String $service_ensure,

) {

  contain ssh::server::install
  contain ssh::server::config
  contain ssh::server::service

  Class['ssh::server::install']
    -> Class['ssh::server::config']
      ~> Class['ssh::server::service']

}

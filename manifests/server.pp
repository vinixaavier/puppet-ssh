# ssh::server
#
# A description of what this class does
#
# @summary A short summary of the purpose of this class
#
# @example
#   include ssh::server
class ssh::server (

  String                   $package_name,
  String                   $package_ensure,
  Stdlib::Absolutepath     $conf_dir,
  Stdlib::Absolutepath     $conf_file,
  Variant[String, Integer] $conf_owner,
  Variant[String, Integer] $conf_group,
  String                   $conf_dir_mode,
  String                   $conf_file_mode,
  String                   $service_name,
  String                   $service_ensure,
  Boolean                  $service_enable,

) {

  contain ssh::server::install
  contain ssh::server::config
  contain ssh::server::service

  Class['ssh::server::install']
    -> Class['ssh::server::config']
      ~> Class['ssh::server::service']

}

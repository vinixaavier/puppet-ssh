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
  Stdlib::Filemode         $conf_dir_mode,
  Stdlib::Filemode         $conf_file_mode,
  String                   $service_name,
  String                   $service_ensure,
  Boolean                  $service_enable,
  Array                    $hostkeys,
  String                   $rekeylimit,
  String                   $loglevel,
  String                   $logingracetime,
  String                   $permitrootlogin,
  String                   $strictmodes,
  Integer                  $maxauthtries,
  Integer                  $maxsessions,
  Enum['yes', 'no']                   $pubkeyauth,
  String                   $authkeysfile,
  String                   $authprincipalsfile,
  String                   $authkeyscommand,
  String                   $authkeyscommanduser,
  String                   $hostbasedauth,
  String                   $ignoreuserknownhosts,
  String                   $ignorerhosts,
  String                   $passwordauth,
  String                   $permitemptypassword,
  String                   $challengeresponseauth,
  String                   $krbsauth,
  String                   $krbsorlocalpasswd,
  String                   $krbsticketcleanup,
  String                   $krbsgetafstoken,
  String                   $krbsusekuserok,


) {

  contain ssh::server::install
  contain ssh::server::config
  contain ssh::server::service

  Class['ssh::server::install']
    -> Class['ssh::server::config']
      ~> Class['ssh::server::service']

}

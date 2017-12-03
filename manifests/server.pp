# ssh::server
#
# A description of what this class does
#
# @summary A short summary of the purpose of this class
#
# @example
#   include ssh::server
class ssh::server (

  String                                $package_name,
  String                                $package_ensure,
  Stdlib::Absolutepath                  $conf_dir,
  Stdlib::Absolutepath                  $conf_file,
  Variant[String, Integer]              $conf_owner,
  Variant[String, Integer]              $conf_group,
  Stdlib::Filemode                      $conf_dir_mode,
  Stdlib::Filemode                      $conf_file_mode,
  String                                $service_name,
  Stdlib::Ensure::Service               $service_ensure,
  Boolean                               $service_enable,
  Optional[Integer[1,65535]]            $port,
  Optional[Enum['ipv4', 'ipv6', 'any']] $addressfamily,
  Optional[String]                      $listenaddress,
  Optional[Array[Stdlib::Absolutepath]] $hostkeys,
  Optional[String]                      $rekeylimit,
  Optional[Pattern[/.*[A-Z]/]]          $syslogfacility,
  Optional[Pattern[/.*[A-Z]/]]          $log_level,
  Optional[String]                      $logingracetime,
  Optional[Enum['yes', 'no']]           $permitrootlogin,
  Optional[Enum['yes', 'no']]           $strictmodes,
  Optional[Integer]                     $maxauthtries,
  Optional[Integer]                     $maxsessions,
  Optional[Enum['yes', 'no']]           $pubkeyauth,
  Optional[String]                      $authkeysfile,
  Optional[String]                      $authprincipalsfile,
  Optional[String]                      $authkeyscommand,
  Optional[String]                      $authkeyscommanduser,
  Optional[Enum['yes', 'no']]           $hostbasedauth,
  Optional[Enum['yes', 'no']]           $ignoreuserknownhosts,
  Optional[Enum['yes', 'no']]           $ignorerhosts,
  Optional[Enum['yes', 'no']]           $passwordauth,
  Optional[Enum['yes', 'no']]           $permitemptypassword,
  Optional[Enum['yes', 'no']]           $challengeresponseauth,
  Optional[Enum['yes', 'no']]           $krbsauth,
  Optional[Enum['yes', 'no']]           $krbsorlocalpasswd,
  Optional[Enum['yes', 'no']]           $krbsticketcleanup,
  Optional[Enum['yes', 'no']]           $krbsgetafstoken,
  Optional[Enum['yes', 'no']]           $krbsusekuserok,
  Optional[Enum['yes', 'no']]           $gssapiauth,
  Optional[Enum['yes', 'no']]           $gssapicleanupcredentials,
  Optional[Enum['yes', 'no']]           $gssapistrictacceptorcheck,
  Optional[Enum['yes', 'no']]           $gssapikeyexchange,
  Optional[Enum['yes', 'no']]           $gssapienablek5users,
  Optional[Enum['yes', 'no']]           $usepam,
  Optional[Enum['yes', 'no']]           $allowagentforwarding,
  Optional[Enum['yes', 'no']]           $allowtcpforwarding,
  Optional[Enum['yes', 'no']]           $gatewayports,
  Optional[Enum['yes', 'no']]           $x11forwarding,
  Optional[Integer]                     $x11displayoffset,
  Optional[Enum['yes', 'no']]           $x11uselocalhost,
  Optional[Enum['yes', 'no']]           $permit_tty,
  Optional[Enum['yes', 'no']]           $printmotd,
  Optional[Enum['yes', 'no']]           $printlastlog,
  Optional[Enum['yes', 'no']]           $tcpkeepalive,
  Optional[Enum['yes', 'no']]           $uselogin,
  Optional[String]                      $useprivilegeseparation,
  Optional[Integer]                     $keyregenerationinterval,
  Optional[Integer]                     $serverkeybits,
  Optional[Enum['yes', 'no']]           $permituserenvironment,
  Optional[String]                      $compression,
  Optional[Integer]                     $clientaliveinterval,
  Optional[Integer]                     $clientalivecountmax,
  Optional[Enum['yes', 'no']]           $showpatchlevel,
  Optional[Enum['yes', 'no']]           $usedns,
  Optional[Stdlib::Absolutepath]        $pidfile,
  Optional[String]                      $maxstartups,
  Optional[Enum['yes', 'no']]           $permit_tunnel,
  Optional[String]                      $chrootdirectory,
  Optional[String]                      $versionaddendum,
  Optional[String]                      $banner,
  Optional[Array]                       $acceptenvs,
  Optional[String]                      $subsystem,

) {

  contain ssh::server::install
  contain ssh::server::config
  contain ssh::server::service

  Class['ssh::server::install']
    -> Class['ssh::server::config']
      ~> Class['ssh::server::service']

}

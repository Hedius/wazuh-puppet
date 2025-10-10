# Copyright (C) 2015, Wazuh Inc.
# Setup for Wazuh Dashboard
# @param dashboard_server_hosts
#   List of URLs to the wazuh-indexers
# @param cert_dir
#   Local directory on server that stores certificates. (Used as a base for copying it to the dashboard server.)
class wazuh::dashboard (
  $dashboard_package = 'wazuh-dashboard',
  $dashboard_service = 'wazuh-dashboard',
  $dashboard_version = '4.13.1',
  $indexer_server_ip = 'localhost',
  Stdlib::Port $indexer_server_port = 9200,
  $manager_api_host = '127.0.0.1',
  $dashboard_path_certs = '/etc/wazuh-dashboard/certs',
  $dashboard_fileuser = 'wazuh-dashboard',
  $dashboard_filegroup = 'wazuh-dashboard',

  Stdlib::Port $dashboard_server_port = 443,
  $dashboard_server_host = '0.0.0.0',
  Array[String] $dashboard_server_hosts = ["https://${indexer_server_ip}:${indexer_server_port}"],

  # If the keystore is used, the credentials are not managed by the module (TODO).
  # If use_keystore is false, the keystore is deleted, the dashboard use the credentials in the configuration file.
  $use_keystore = true,
  $dashboard_user = 'kibanaserver',
  $dashboard_password = 'kibanaserver',

  $dashboard_wazuh_api_credentials = [
    {
      'id'       => 'default',
      'url'      => "https://${manager_api_host}",
      'port'     => '55000',
      'user'     => 'wazuh-wui',
      'password' => 'wazuh-wui',
    },
  ],

  Stdlib::Absolutepath $cert_dir = '/etc/wazuh-certs',
) {
  # assign version according to the package manager
  case $facts['os']['family'] {
    'Debian': {
      $dashboard_version_install = "${dashboard_version}-*"
    }
    'Linux', 'RedHat', default: {
      $dashboard_version_install = $dashboard_version
    }
  }

  # install package
  package { 'wazuh-dashboard':
    ensure => $dashboard_version_install,
    name   => $dashboard_package,
  }
  # todo pin package

  exec { "ensure full path of ${dashboard_path_certs}":
    path    => '/usr/bin:/bin',
    command => "mkdir -p ${dashboard_path_certs}",
    creates => $dashboard_path_certs,
    require => Package['wazuh-dashboard'],
  }
  -> file { $dashboard_path_certs:
    ensure => directory,
    owner  => $dashboard_fileuser,
    group  => $dashboard_filegroup,
    mode   => '0500',
  }

  $certs = {
    'root-ca' => 'root-ca',
    'dashboard' => $trusted['hostname'],
    'dashboard-key' => "${trusted['hostname']}-key",
  }
  $certs.each |String $certfile, String $certsource| {
    file { "${dashboard_path_certs}/${certfile}.pem":
      ensure    => file,
      owner     => $dashboard_fileuser,
      group     => $dashboard_filegroup,
      mode      => '0400',
      replace   => true,
      recurse   => remote,
      source    => "${cert_dir}/${certsource}.pem",
      show_diff => false,
    }
  }

  $config = {
    'server.host'                              => $dashboard_server_host,
    'server.port'                              => $dashboard_server_port,
    'opensearch.hosts'                         => $dashboard_server_hosts,
    'opensearch.ssl.verificationMode'          => 'certificate',
    'opensearch.requestHeadersWhitelist'       => ['securitytenant', 'Authorization'],
    'opensearch_security.multitenancy.enabled' => false,
    'opensearch_security.readonly_mode.roles'  => ['kibana_read_only'],
    'server.ssl.enabled'                       => true,
    'server.ssl.key'                           => "${dashboard_path_certs}/dashboard-key.pem",
    'server.ssl.certificate'                   => "${dashboard_path_certs}/dashboard.pem",
    'opensearch.ssl.certificateAuthorities'    => ["${dashboard_path_certs}/root-ca.pem"],
    'uiSettings.overrides.defaultRoute'        => '/app/wz-home',
    # Session epiration settings
    'opensearch_security.cookie.ttl'           => 900000,
    'opensearch_security.session.ttl'          => 900000,
    'opensearch_security.session.keepalive'    => true,
    'opensearch.username'                      => $dashboard_user,
    'opensearch.password'                      => $dashboard_password,
  }

  $config_file = '/etc/wazuh-dashboard/opensearch_dashboards.yml'
  file { '/etc/wazuh-dashboard':
    ensure => directory,
    owner  => $dashboard_fileuser,
    group  => $dashboard_filegroup,
    mode   => '0750',
  }
  -> file { $config_file:
    content   => stdlib::to_yaml($config),
    group     => $dashboard_filegroup,
    mode      => '0640',
    owner     => $dashboard_fileuser,
    require   => Package['wazuh-dashboard'],
    notify    => Service['wazuh-dashboard'],
    show_diff => false,
  }

  file { ['/usr/share/wazuh-dashboard/data/wazuh/', '/usr/share/wazuh-dashboard/data/wazuh/config']:
    ensure  => 'directory',
    group   => $dashboard_filegroup,
    mode    => '0755',
    owner   => $dashboard_fileuser,
    require => Package['wazuh-dashboard'],
  }
  -> file { '/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml':
    content   => template('wazuh/wazuh_yml.erb'),
    group     => $dashboard_filegroup,
    mode      => '0600',
    owner     => $dashboard_fileuser,
    notify    => Service['wazuh-dashboard'],
    show_diff => false,
  }

  unless $use_keystore {
    file { '/etc/wazuh-dashboard/opensearch_dashboards.keystore':
      ensure  => absent,
      require => Package['wazuh-dashboard'],
      before  => Service['wazuh-dashboard'],
    }
  } else {
    exec { 'update-dashboard-pw':
      # Exec Update pw in dashboard keystore whenever smth changes here
      # E.g. we write a new kibanaserver pw into the config file.
      # command stolen from the wazuh pw tool scripts
      # lint:ignore:140chars
      command     => "echo \"${dashboard_password}\" | /usr/share/wazuh-dashboard/bin/opensearch-dashboards-keystore --allow-root add -f --stdin opensearch.password > /dev/null 2>&1",
      # lint:endignore,
      path        => $facts['path'],
      refreshonly => true,
      subscribe   => File[$config_file],
      notify      => Service['wazuh-dashboard'],
    }
  }

  service { 'wazuh-dashboard':
    ensure     => running,
    enable     => true,
    hasrestart => true,
    name       => $dashboard_service,
  }
}

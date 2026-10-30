# Copyright (C) 2015, Wazuh Inc.
# Setup for Wazuh Indexer
# @param config
#   Config overrides
# @param jvm_options_memory
#   Explicit heap size for the indexer JVM (used for -Xms and -Xmx, e.g. '4096M').
#   If unset, it is computed as 50% of RAM, capped at 32GB, minus 1GB when the
#   dashboard and a further 4GB when the manager run on the same node.
# @param with_dashboard
#   Whether the Wazuh dashboard runs on this node, which reserves 1GB of RAM from
#   the computed heap. If undef, detected via defined(Class['wazuh::dashboard']).
#   Might not catch it.... so the param can manually trigger the logic.
# @param with_manager
#   Whether the Wazuh manager (server) runs on this node, which reserves 4GB of RAM
#   from the computed heap. If undef, detected via defined(Class['wazuh::manager']),
#   Might not catch it.... so the param can manually trigger the logic.
# @param jvm_min_memory_mb
#   Lower bound in MB for the computed heap size.
class wazuh::indexer (
  # opensearch.yml configuration
  $indexer_network_host = '0.0.0.0',
  $indexer_cluster_name = 'wazuh-cluster',
  $indexer_node_name = 'node-1',
  $indexer_node_max_local_storage_nodes = '1',
  $indexer_service = 'wazuh-indexer',
  $indexer_package = 'wazuh-indexer',
  $indexer_version = '4.14.9',
  $indexer_fileuser = 'wazuh-indexer',
  $indexer_filegroup = 'wazuh-indexer',

  $indexer_path_data = '/var/lib/wazuh-indexer',
  $indexer_path_logs = '/var/log/wazuh-indexer',
  $indexer_path_certs = '/etc/wazuh-indexer/certs',
  $indexer_security_init_lockfile = '/var/tmp/indexer-security-init.lock',
  $full_indexer_reinstall = false, # Change to true when whant a full reinstall of Wazuh indexer

  $indexer_ip = 'localhost',
  $indexer_port = '9200',
  $indexer_discovery_hosts = [], # Empty array for single-node configuration
  $indexer_cluster_initial_master_nodes = ['node-1'],
  $indexer_cluster_cn = ['node-1'],

  $ca_org = 'OU=Wazuh,O=Wazuh,L=California,C=US',
  $admin_dn = ['admin'],
  Stdlib::Absolutepath $cert_dir = '/etc/wazuh-certs',

  # JVM options
  Optional[String] $jvm_options_memory = undef,
  Optional[Boolean] $with_dashboard = undef,
  Optional[Boolean] $with_manager = undef,
  Integer $jvm_min_memory_mb = 2048,

  Hash $config = {}
) {
  if $jvm_options_memory {
    $_jvm_options_memory = $jvm_options_memory
  } else {
    $_with_dashboard = pick($with_dashboard, defined(Class['wazuh::dashboard']))
    $_with_manager = pick($with_manager, defined(Class['wazuh::manager']))

    # reserve 1GB for the dashboard and 4GB for the manager when on the same node
    $reserved_dashboard_mb = $_with_dashboard ? { true => 1024, default => 0 }
    $reserved_manager_mb = $_with_manager ? { true => 4 * 1024, default => 0 }
    $reserved_mb = $reserved_dashboard_mb + $reserved_manager_mb

    # cap at 32GB, else 50% of RAM, minus reserved memory, but never below the minimum
    $base_mb = [32 * 1024, $facts['memory']['system']['total_bytes'] / 1024 / 1024 / 2].sort[0].floor
    $mem = [$base_mb - $reserved_mb, $jvm_min_memory_mb].sort[-1]
    $_jvm_options_memory = "${mem}M"
  }

  # assign version according to the package manager
  case $facts['os']['family'] {
    'Debian': {
      # todo check this
      $indexer_version_install = "${indexer_version}-${indexer_revision}"
    }
    'Linux', 'RedHat', default: {
      $indexer_version_install = $indexer_version
    }
  }

  # install package
  if $facts['os']['family'] == 'Debian' {
    apt::pin { 'wazuh-indexer':
      packages => $indexer_package,
      priority => 1001,
      version  => $indexer_version_install,
      notify   => Class['apt::update'],
    }
  }
  package { 'wazuh-indexer':
    ensure => $indexer_version_install,
    name   => $indexer_package,
  }
  # todo pin the package

  exec { "ensure full path of ${indexer_path_certs}":
    path    => '/usr/bin:/bin',
    command => "mkdir -p ${indexer_path_certs}",
    creates => $indexer_path_certs,
    require => Package['wazuh-indexer'],
  }
  -> file { $indexer_path_certs:
    ensure => directory,
    owner  => $indexer_fileuser,
    group  => $indexer_filegroup,
    mode   => '0500',
  }

  # New type sinc crt tool has a different logic now. generates hostname.pem no longer indexer-hostname.pem
  $certs = {
    'root-ca' => 'root-ca',
    'admin' => 'admin',
    'admin-key' => 'admin-key',
    'indexer' => $trusted['hostname'],
    'indexer-key' => "${trusted['hostname']}-key",
  }

  $certs.each |String $certfile, String $certsource| {
    file { "${indexer_path_certs}/${certfile}.pem":
      ensure    => file,
      owner     => $indexer_fileuser,
      group     => $indexer_filegroup,
      mode      => '0400',
      replace   => true,
      recurse   => remote,
      # todo - same crt workaround
      source    => "${cert_dir}/${certsource}.pem",
      notify    => Service['wazuh-indexer'],
      show_diff => false,
    }
  }

  unless $indexer_discovery_hosts.empty {
    $setting_seed_hosts = { 'discovery.seed_hosts' => $indexer_discovery_hosts }
  } else {
    $setting_seed_hosts = {}
  }

  $default_config = {
    'network.host' => $indexer_network_host,
    'node.name' => $indexer_node_name,
    'cluster.initial_master_nodes' => $indexer_cluster_initial_master_nodes,
    'cluster.name' => $indexer_cluster_name,
    'discovery.seed_hosts' => $indexer_discovery_hosts,
    'node.max_local_storage_nodes' => $indexer_node_max_local_storage_nodes,
    'path.data' => $indexer_path_data,
    'path.logs' => $indexer_path_logs,
    'plugins.security.ssl.http.pemcert_filepath' => "${indexer_path_certs}/indexer.pem",
    'plugins.security.ssl.http.pemkey_filepath' => "${indexer_path_certs}/indexer-key.pem",
    'plugins.security.ssl.http.pemtrustedcas_filepath' => "${indexer_path_certs}/root-ca.pem",
    'plugins.security.ssl.transport.pemcert_filepath' => "${indexer_path_certs}/indexer.pem",
    'plugins.security.ssl.transport.pemkey_filepath' => "${indexer_path_certs}/indexer-key.pem",
    'plugins.security.ssl.transport.pemtrustedcas_filepath' => "${indexer_path_certs}/root-ca.pem",
    'plugins.security.ssl.http.enabled' => true,
    'plugins.security.ssl.transport.enforce_hostname_verification' => false,
    'plugins.security.ssl.transport.resolve_hostname' => false,
    'plugins.security.authcz.admin_dn' => $admin_dn.map|$cn| { "CN=${cn},${ca_org}" },
    'plugins.security.check_snapshot_restore_write_privileges' => true,
    'plugins.security.enable_snapshot_restore_privilege' => true,
    'plugins.security.nodes_dn' => $indexer_cluster_cn.map|$cn| { "CN=${cn},${ca_org}" },
    'plugins.security.restapi.roles_enabled' => ['all_access', 'security_rest_api_access'],
    'plugins.security.allow_default_init_securityindex' => true,
    'cluster.routing.allocation.disk.threshold_enabled' => false,
    'compatibility.override_main_response_version' => true,
  } + $setting_seed_hosts

  file { 'configuration file':
    path    => '/etc/wazuh-indexer/opensearch.yml',
    content => stdlib::to_yaml(deep_merge($default_config, $config)),
    group   => $indexer_filegroup,
    mode    => '0660',
    owner   => $indexer_fileuser,
    require => Package['wazuh-indexer'],
    notify  => Service['wazuh-indexer'],
  }

  file_line { 'Insert line initial size of total heap space':
    path    => '/etc/wazuh-indexer/jvm.options',
    line    => "-Xms${_jvm_options_memory}",
    match   => '^-Xms',
    require => Package['wazuh-indexer'],
    notify  => Service['wazuh-indexer'],
  }

  file_line { 'Insert line maximum size of total heap space':
    path    => '/etc/wazuh-indexer/jvm.options',
    line    => "-Xmx${_jvm_options_memory}",
    match   => '^-Xmx',
    require => Package['wazuh-indexer'],
    notify  => Service['wazuh-indexer'],
  }

  service { 'wazuh-indexer':
    ensure   => running,
    enable   => true,
    name     => $indexer_service,
    require  => Package['wazuh-indexer'],
    provider => 'systemd',
  }

  file_line { "Insert line limits nofile for ${indexer_fileuser}":
    path   => '/etc/security/limits.conf',
    line   => "${indexer_fileuser} - nofile  65535",
    match  => "^${indexer_fileuser} - nofile\s",
    notify => Service['wazuh-indexer'],
  }
  file_line { "Insert line limits memlock for ${indexer_fileuser}":
    path   => '/etc/security/limits.conf',
    line   => "${indexer_fileuser} - memlock unlimited",
    match  => "^${indexer_fileuser} - memlock\s",
    notify => Service['wazuh-indexer'],
  }

  if $full_indexer_reinstall {
    file { $indexer_security_init_lockfile:
      ensure  => absent,
      require => Package['wazuh-indexer'],
      before  => Exec['Initialize the Opensearch security index in Wazuh indexer'],
    }
  }
}

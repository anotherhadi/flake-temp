{ pkgs, lib, config, ... }:
let version = "4.7.3";
in {

  imports = [ ./certs.nix ];

  options.programs.wazuh = {
    enable = lib.mkEnableOption "Enable Wazuh stack";
  };

  config = lib.mkIf config.programs.wazuh.enable {
    # Since we use "--network=host" we need to add the hostnames to /etc/hosts
    networking.extraHosts = ''
      127.0.0.1 wazuh.manager wazuh.indexer wazuh.dashboard
    '';

    networking.firewall = {
      allowedTCPPorts = [ 1514 1515 55000 9200 5601 ];
      allowedUDPPorts = [ 514 ];
    };

    environment.etc."wazuh/config" = { source = ./config; };

    environment.etc."wazuh/docker-compose.yml".text =
      #yaml
      ''
        # Wazuh App Copyright (C) 2017, Wazuh Inc. (License GPLv2)
        version: '3.7'
        services:
          wazuh.manager:
            image: wazuh/wazuh-manager:5.0.0
            hostname: wazuh.manager
            restart: unless-stopped
            ulimits:
              memlock:
                soft: -1
                hard: -1
              nofile:
                soft: 655360
                hard: 655360
            ports:
              - "1514:1514"
              - "1515:1515"
              - "514:514/udp"
              - "55000:55000"
            environment:
              INDEXER_URL: https://wazuh.indexer:9200
              INDEXER_USERNAME: admin
              INDEXER_PASSWORD: admin
              FILEBEAT_SSL_VERIFICATION_MODE: full
              SSL_CERTIFICATE_AUTHORITIES: /etc/ssl/root-ca.pem
              SSL_CERTIFICATE: /etc/ssl/filebeat.pem
              SSL_KEY: /etc/ssl/filebeat.key
              API_USERNAME: wazuh-wui
              API_PASSWORD: MyS3cr37P450r.*-
            volumes:
              - wazuh_api_configuration:/var/ossec/ap/etc/wazuh/configuration
              - wazuh_etc:/var/ossec/etc
              - wazuh_logs:/var/ossec/logs
              - wazuh_queue:/var/ossec/queue
              - wazuh_var_multigroups:/var/ossec/var/multigroups
              - wazuh_integrations:/var/ossec/integrations
              - wazuh_active_response:/var/ossec/active-response/bin
              - wazuh_agentless:/var/ossec/agentless
              - wazuh_wodles:/var/ossec/wodles
              - filebeat_etc:/etc/filebeat
              - filebeat_var:/var/lib/filebeat
              - /etc/wazuh/certs/root-ca-manager.pem:/etc/ssl/root-ca.pem
              - /etc/wazuh/certs/wazuh.manager.pem:/etc/ssl/filebeat.pem
              - /etc/wazuh/certs/wazuh.manager-key.pem:/etc/ssl/filebeat.key
              - /etc/wazuh/config/wazuh_cluster/wazuh_manager.conf:/wazuh-config-mount/etc/ossec.conf

          wazuh.indexer:
            image: wazuh/wazuh-indexer:5.0.0
            hostname: wazuh.indexer
            restart: unless-stopped
            ulimits:
              memlock:
                soft: -1
                hard: -1
              nofile:
                soft: 65536
                hard: 65536
            ports:
              - "9200:9200"
            environment:
              OPENSEARCH_JAVA_OPTS: "-Xms1g -Xmx1g"
              bootstrap.memory_lock: "true"
              NODE_NAME: "wazuh.indexer"
              CLUSTER_INITIAL_MASTER_NODES: "wazuh.indexer"
              CLUSTER_NAME: "wazuh-cluster"
              PATH_DATA: /var/lib/wazuh-indexer
              PATH_LOGS: /var/log/wazuh-indexer
              HTTP_PORT: 9200-9299
              TRANSPORT_TCP_PORT: 9300-9399
              COMPATIBILITY_OVERRIDE_MAIN_RESPONSE_VERSION: "true"
              PLUGINS_SECURITY_SSL_HTTP_PEMCERT_FILEPATH: /usr/share/wazuh-indexer/certs/wazuh.indexer.pem
              PLUGINS_SECURITY_SSL_HTTP_PEMKEY_FILEPATH: /usr/share/wazuh-indexer/certs/wazuh.indexer.key
              PLUGINS_SECURITY_SSL_HTTP_PEMTRUSTEDCAS_FILEPATH: /usr/share/wazuh-indexer/certs/root-ca.pem
              PLUGINS_SECURITY_SSL_TRANSPORT_PEMCERT_FILEPATH: /usr/share/wazuh-indexer/certs/wazuh.indexer.pem
              PLUGINS_SECURITY_SSL_TRANSPORT_PEMKEY_FILEPATH: /usr/share/wazuh-indexer/certs/wazuh.indexer.key
              PLUGINS_SECURITY_SSL_TRANSPORT_PEMTRUSTEDCAS_FILEPATH: /usr/share/wazuh-indexer/certs/root-ca.pem
              PLUGINS_SECURITY_SSL_HTTP_ENABLED: "true"
              PLUGINS_SECURITY_SSL_TRANSPORT_ENFORCE_HOSTNAME_VERIFICATION: "false"
              PLUGINS_SECURITY_SSL_TRANSPORT_RESOLVE_HOSTNAME: "false"
              PLUGINS_SECURITY_AUTHCZ_ADMIN_DN: "CN=admin,OU=Wazuh,O=Wazuh,L=California,C=US"
              PLUGINS_SECURITY_CHECK_SNAPSHOT_RESTORE_WRITE_PRIVILEGES: "true"
              PLUGINS_SECURITY_ENABLE_SNAPSHOT_RESTORE_PRIVILEGE: "true"
              PLUGINS_SECURITY_NODES_DN: "CN=wazuh.indexer,OU=Wazuh,O=Wazuh,L=California,C=US"
              PLUGINS_SECURITY_RESTAPI_ROLES_ENABLED: '["all_access", "security_rest_api_access"]'
              PLUGINS_SECURITY_SYSTEM_INDICES_ENABLED: "true"
              PLUGINS_SECURITY_SYSTEM_INDICES_INDICES: '[".opendistro-alerting-config", ".opendistro-alerting-alert*", ".opendistro-anomaly-results*", ".opendistro-anomaly-detector*", ".opendistro-anomaly-checkpoints", ".opendistro-anomaly-detection-state", ".opendistro-reports-*", ".opendistro-notifications-*", ".opendistro-notebooks", ".opensearch-observability", ".opendistro-asynchronous-search-response*", ".replication-metadata-store"]'
              PLUGINS_SECURITY_ALLOW_DEFAULT_INIT_SECURITYINDEX: "true"
              CLUSTER_ROUTING_ALLOCATION_DISK_THRESHOLD_ENABLED: "false"
            volumes:
              - wazuh-indexer-data:/var/lib/wazuh-indexer
              - /etc/wazuh/certs/root-ca.pem:/usr/share/wazuh-indexer/certs/root-ca.pem
              - /etc/wazuh/certs/wazuh.indexer-key.pem:/usr/share/wazuh-indexer/certs/wazuh.indexer.key
              - /etc/wazuh/certs/wazuh.indexer.pem:/usr/share/wazuh-indexer/certs/wazuh.indexer.pem
              - /etc/wazuh/certs/admin.pem:/usr/share/wazuh-indexer/certs/admin.pem
              - /etc/wazuh/certs/admin-key.pem:/usr/share/wazuh-indexer/certs/admin-key.pem
              #  if you need mount a custom opensearch.yml, uncomment the next line and delete the environment variables
              # - /etc/wazuh/config/wazuh_indexer/wazuh.indexer.yml:/usr/share/wazuh-indexer/opensearch.yml

          wazuh.dashboard:
            image: wazuh/wazuh-dashboard:5.0.0
            hostname: wazuh.dashboard
            restart: unless-stopped
            ulimits:
              memlock:
                soft: -1
                hard: -1
              nofile:
                soft: 65536
                hard: 65536
            ports:
              - 443:5601
            environment:
              WAZUH_API_URL: https://wazuh.manager
              DASHBOARD_USERNAME: kibanaserver
              DASHBOARD_PASSWORD: kibanaserver
              API_USERNAME: wazuh-wui
              API_PASSWORD: MyS3cr37P450r.*-
              SERVER_HOST: 0.0.0.0
              SERVER_PORT: 5601
              OPENSEARCH_HOSTS: https://wazuh.indexer:9200
              OPENSEARCH_SSL_VERIFICATIONMODE: certificate
              OPENSEARCH_REQUESTHEADERSALLOWLIST: '["securitytenant","Authorization"]'
              OPENSEARCH_SECURITY_MULTITENANCY_ENABLED: "false"
              SERVER_SSL_ENABLED: "true"
              OPENSEARCH_SECURITY_READONLY_MODE_ROLES: '["kibana_read_only"]'
              SERVER_SSL_KEY: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
              SERVER_SSL_CERTIFICATE: "/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem"
              OPENSEARCH_SSL_CERTIFICATEAUTHORITIES: '["/usr/share/wazuh-dashboard/certs/root-ca.pem"]'
              UISETTINGS_OVERRIDES_DEFAULTROUTE: /app/wz-home
            volumes:
              - wazuh-dashboard-config:/usr/share/wazuh-dashboard/data/wazu/etc/wazuh/config
              - wazuh-dashboard-custom:/usr/share/wazuh-dashboard/plugins/wazuh/public/assets/custom
              - /etc/wazuh/certs/wazuh.dashboard.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem
              - /etc/wazuh/certs/wazuh.dashboard-key.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem
              - /etc/wazuh/certs/root-ca.pem:/usr/share/wazuh-dashboard/certs/root-ca.pem
              - /etc/wazuh/config/wazuh_dashboard/wazuh.yml:/wazuh-config-mount/data/wazuh/config/wazuh.yml
              #  if you need mount a custom opensearch-dashboards.yml, uncomment the next line and delete the environment variables
              # - /etc/wazuh/config/wazuh_dashboard/opensearch_dashboards.yml:/wazuh-config-mount/config/opensearch_dashboards.yml
            depends_on:
              - wazuh.indexer
            links:
              - wazuh.indexer:wazuh.indexer
              - wazuh.manager:wazuh.manager

        volumes:
          wazuh_api_configuration:
          wazuh_etc:
          wazuh_logs:
          wazuh_queue:
          wazuh_var_multigroups:
          wazuh_integrations:
          wazuh_active_response:
          wazuh_agentless:
          wazuh_wodles:
          filebeat_etc:
          filebeat_var:
          wazuh-indexer-data:
          wazuh-dashboard-config:
          wazuh-dashboard-custom:
      '';

    systemd.services.wazuh-docker = {
      description = "Start Wazuh containers using Docker Compose";
      after = [ "generate-wazuh-certs.service" "docker.service" ];
      requires = [ "docker.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "simple";
        WorkingDirectory = "/etc/wazuh";
        ExecStart = "${pkgs.docker-compose}/bin/docker-compose up -d";
        ExecStop = "${pkgs.docker-compose}/bin/docker-compose down";
        Restart = "always";
      };
    };
  };
}

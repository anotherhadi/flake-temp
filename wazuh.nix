{ pkgs, lib, config, ... }:
let
  version = "4.10.1";

  wazuh-reload = pkgs.writeShellScriptBin "wazuh-reload" ''
    set -e
    sleep 60

    INSTALLATION_DIR=/usr/share/wazuh-indexer
    ${pkgs.docker}/bin/docker exec \
        -e JAVA_HOME=/usr/share/wazuh-indexer/jdk \
        wazuh-wazuh.indexer-1 \
        /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security/ -nhnv -cacert  $INSTALLATION_DIR/certs/root-ca.pem -cert $INSTALLATION_DIR/certs/admin.pem -key $INSTALLATION_DIR/certs/admin-key.pem -p 9200 -icl
  '';
in {

  imports = [ ./certs.nix ];

  options.programs.wazuh = {
    enable = lib.mkEnableOption "Enable Wazuh stack";

    username = lib.mkOption {
      type = lib.types.str;
      default = "admin";
      description = "Username for Wazuh";
    };

    password = lib.mkOption {
      type = lib.types.str;
      default = "HMthisismys3cr3tP5ssword34a;";
      description = "Password for Wazuh";
    };

    hashedPassword = lib.mkOption {
      type = lib.types.str;
      default = "$2y$12$MHyIz80KY58QdLxCQoRZv.k0kKt6WA6pwmAa4apPV.e2KrR1SslNC";
      description = "Bcrypt hashed password for Wazuh";
    };
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

    environment.etc."wazuh/config/wazuh_cluster" = {
      source = ./config/wazuh_cluster;
    };
    environment.etc."wazuh/config/wazuh_dashboard/opensearch_dashboards.yml" = {
      source = ./config/wazuh_dashboard/opensearch_dashboards.yml;
    };
    environment.etc."wazuh/config/wazuh_indexer/wazuh.indexer.yml" = {
      source = ./config/wazuh_indexer/wazuh.indexer.yml;
    };
    environment.etc."wazuh/config/wazuh_dashboard/wazuh.yml".text = ''
      hosts:
        - 1513629884013:
            url: "https://wazuh.manager"
            port: 55000
            username: ${config.programs.wazuh.username}
            password: "${config.programs.wazuh.password}"
            run_as: false
    '';
    environment.etc."wazuh/config/wazuh_indexer/internal_users.yml".text = ''
      ---
      # This is the internal user database
      # The hash value is a bcrypt hash and can be generated with plugin/tools/hash.sh

      _meta:
        type: "internalusers"
        config_version: 2

      # Define your internal users here

      ## Demo users

      admin:
        hash: "${config.programs.wazuh.hashedPassword}"
        reserved: true
        backend_roles:
        - "admin"
    '';

    environment.etc."wazuh/config/certs.yml" = { source = ./config/certs.yml; };

    environment.etc."wazuh/docker-compose.yml".text =
      #yaml
      ''
        # Wazuh App Copyright (C) 2017, Wazuh Inc. (License GPLv2)
        services:
          wazuh.manager:
            image: wazuh/wazuh-manager:${version}
            hostname: wazuh.manager
            restart: always
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
              - INDEXER_URL=https://wazuh.indexer:9200
              - INDEXER_USERNAME=${config.programs.wazuh.username}
              - INDEXER_PASSWORD=${config.programs.wazuh.password}
              - FILEBEAT_SSL_VERIFICATION_MODE=full
              - SSL_CERTIFICATE_AUTHORITIES=/etc/ssl/root-ca.pem
              - SSL_CERTIFICATE=/etc/ssl/filebeat.pem
              - SSL_KEY=/etc/ssl/filebeat.key
              - API_USERNAME=${config.programs.wazuh.username}
              - API_PASSWORD=${config.programs.wazuh.password}
            volumes:
              - wazuh_api_configuration:/var/ossec/api/configuration
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
              - ./config/wazuh_indexer_ssl_certs/root-ca-manager.pem:/etc/ssl/root-ca.pem
              - ./config/wazuh_indexer_ssl_certs/wazuh.manager.pem:/etc/ssl/filebeat.pem
              - ./config/wazuh_indexer_ssl_certs/wazuh.manager-key.pem:/etc/ssl/filebeat.key
              - ./config/wazuh_cluster/wazuh_manager.conf:/wazuh-config-mount/etc/ossec.conf

          wazuh.indexer:
            image: wazuh/wazuh-indexer:4.10.1
            hostname: wazuh.indexer
            restart: always
            ports:
              - "9200:9200"
            environment:
              - "OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g"
            ulimits:
              memlock:
                soft: -1
                hard: -1
              nofile:
                soft: 65536
                hard: 65536
            volumes:
              - wazuh-indexer-data:/var/lib/wazuh-indexer
              - ./config/wazuh_indexer_ssl_certs/root-ca.pem:/usr/share/wazuh-indexer/certs/root-ca.pem
              - ./config/wazuh_indexer_ssl_certs/wazuh.indexer-key.pem:/usr/share/wazuh-indexer/certs/wazuh.indexer.key
              - ./config/wazuh_indexer_ssl_certs/wazuh.indexer.pem:/usr/share/wazuh-indexer/certs/wazuh.indexer.pem
              - ./config/wazuh_indexer_ssl_certs/admin.pem:/usr/share/wazuh-indexer/certs/admin.pem
              - ./config/wazuh_indexer_ssl_certs/admin-key.pem:/usr/share/wazuh-indexer/certs/admin-key.pem
              - ./config/wazuh_indexer/wazuh.indexer.yml:/usr/share/wazuh-indexer/opensearch.yml
              - ./config/wazuh_indexer/internal_users.yml:/usr/share/wazuh-indexer/opensearch-security/internal_users.yml

          wazuh.dashboard:
            image: wazuh/wazuh-dashboard:4.10.1
            hostname: wazuh.dashboard
            restart: always
            ports:
              - 443:5601
            environment:
              - INDEXER_USERNAME=admin
              - INDEXER_PASSWORD=SecretPassword
              - WAZUH_API_URL=https://wazuh.manager
              - DASHBOARD_USERNAME=${config.programs.wazuh.username}
              - DASHBOARD_PASSWORD=${config.programs.wazuh.password}
              - API_USERNAME=${config.programs.wazuh.username}
              - API_PASSWORD=${config.programs.wazuh.password}
            volumes:
              - ./config/wazuh_indexer_ssl_certs/wazuh.dashboard.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem
              - ./config/wazuh_indexer_ssl_certs/wazuh.dashboard-key.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem
              - ./config/wazuh_indexer_ssl_certs/root-ca.pem:/usr/share/wazuh-dashboard/certs/root-ca.pem
              - ./config/wazuh_dashboard/opensearch_dashboards.yml:/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml
              - ./config/wazuh_dashboard/wazuh.yml:/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
              - wazuh-dashboard-config:/usr/share/wazuh-dashboard/data/wazuh/config
              - wazuh-dashboard-custom:/usr/share/wazuh-dashboard/plugins/wazuh/public/assets/custom
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
      after = [ "wazuh-certs.service" "docker.service" ];
      requires = [ "docker.service" ];
      wantedBy = [ "multi-user.target" "wazuh-docker-watch.path" ];
      serviceConfig = {
        Type = "simple";
        WorkingDirectory = "/etc/wazuh";
        ExecStart = "${pkgs.docker-compose}/bin/docker-compose up";
        ExecStop = "${pkgs.docker-compose}/bin/docker-compose down";
        Restart = "always";
      };
    };

    systemd.services.wazuh-reload-auth = {
      description = "";
      after = [ "wazuh-docker.service" "docker.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${wazuh-reload}/bin/wazuh-reload";
      };
    };

    systemd.paths.wazuh-config-watch = {
      description = "Watch Wazuh config changes";
      pathConfig = {
        PathModified = [ "/etc/wazuh/config" "/etc/wazuh/docker-compose.yml" ];
      };
      wantedBy = [ "multi-user.target" ];
    };
  };
}

{ pkgs, lib, config, ... }:
let
  version = "4.7.3";
  ulimits = [ "--ulimit" "memlock=-1:-1" ];
  wazuh = {
    manager = {
      hostname = "wazuh.manager";
      image = pkgs.dockerTools.pullImage {
        imageName = "wazuh/wazuh-manager";
        imageDigest =
          "sha256:8b418c4faf64e5ba8d9f16f20f9697a16b371058c7b2d7be6ff7e88de54e8603";
        finalImageTag = version;
        sha256 = "sha256-EKxBbJv9c9/jdjITPtGERlyxSZmhZWeGzqq0TIZqQgc=";
      };
    };
    indexer = {
      hostname = "wazuh.indexer";
      image = pkgs.dockerTools.pullImage {
        imageName = "wazuh/wazuh-indexer";
        imageDigest =
          "sha256:b976a99ec2d0311ee468d3e9ab4abebd941aea1bb4b32b337216e8cb63c8be3b";
        finalImageTag = version;
        sha256 = "sha256-isgFZPuQWGlXM3zyOdAd4rbP0r+qM/myMlMAXtJaz2c=";
      };
    };
    dashboard = {
      hostname = "wazuh.dashboard";
      image = pkgs.dockerTools.pullImage {
        imageName = "wazuh/wazuh-dashboard";
        imageDigest =
          "sha256:f151b074dce5b1f95fa5490359a2b34d5c8b0331e264fe26beb3ef48f8375bde";
        finalImageTag = version;
        sha256 = "sha256-xCeWyDwVxBkprIgqCn3x6UKx474+c+ZLx9LW/mrHYus=";
      };
    };
  };
in {

  imports = [ ./certs.nix ];

  options.programs.wazuh = {
    enable = lib.mkEnableOption "Enable Wazuh stack";

    indexerUsername = lib.mkOption {
      type = lib.types.str;
      default = "admin";
      description = "Username for the Wazuh Indexer";
    };

    indexerPassword = lib.mkOption {
      type = lib.types.str;
      default = "MyS3cr37P450r.*-.";
      description = "Password for the Wazuh Indexer";
    };

    apiUsername = lib.mkOption {
      type = lib.types.str;
      default = "admin";
      description = "Username for the Wazuh API";
    };

    apiPassword = lib.mkOption {
      type = lib.types.str;
      default = "MyS3cr37P450r.*-.";
      description = "Password for the Wazuh API";
    };

    dashboardUsername = lib.mkOption {
      type = lib.types.str;
      default = "admin";
      description = "Username for the Wazuh Dashboard";
    };

    dashboardPassword = lib.mkOption {
      type = lib.types.str;
      default = "MyS3cr37P450r.*-.";
      description = "Password for the Wazuh Dashboard";
    };
  };

  config = lib.mkIf config.programs.wazuh.enable {
    # Since we use "--network=host" we need to add the hostnames to /etc/hosts
    networking.extraHosts = ''
      127.0.0.1 ${wazuh.manager.hostname} ${wazuh.indexer.hostname} ${wazuh.dashboard.hostname}
    '';

    networking.firewall = {
      allowedTCPPorts = [ 1514 1515 55000 9200 5601 ];
      allowedUDPPorts = [ 514 ];
    };

    virtualisation.oci-containers = {
      backend = "docker";
      containers = {

        wazuh-manager = {
          hostname = wazuh.manager.hostname;
          image = "wazuh/wazuh-manager:${version}";
          imageFile = wazuh.manager.image;
          autoStart = true;
          extraOptions = [ "--network=host" "--ulimit" "nofile=655360:655360" ]
            ++ ulimits;
          environment = {
            INDEXER_URL = "https://${wazuh.indexer.hostname}:9200";
            INDEXER_USERNAME = config.programs.wazuh.indexerUsername;
            INDEXER_PASSWORD = config.programs.wazuh.indexerPassword;
            FILEBEAT_SSL_VERIFICATION_MODE = "full";
            SSL_CERTIFICATE_AUTHORITIES = "/etc/ssl/root-ca.pem";
            SSL_CERTIFICATE = "/etc/ssl/filebeat.pem";
            SSL_KEY = "/etc/ssl/filebeat.key";
            API_USERNAME = config.programs.wazuh.apiUsername;
            API_PASSWORD = config.programs.wazuh.apiPassword;
          };
          ports = [ "1514:1514" "1515:1515" "514:514/udp" "55000:55000" ];
          volumes = [
            "wazuh_api_configuration:/var/ossec/api/configuration"
            "wazuh_etc:/var/ossec/etc"
            "wazuh_logs:/var/ossec/logs"
            "wazuh_queue:/var/ossec/queue"
            "wazuh_var_multigroups:/var/ossec/var/multigroups"
            "wazuh_integrations:/var/ossec/integrations"
            "wazuh_active_response:/var/ossec/active-response/bin"
            "wazuh_agentless:/var/ossec/agentless"
            "wazuh_wodles:/var/ossec/wodles"
            "filebeat_etc:/etc/filebeat"
            "filebeat_var:/var/lib/filebeat"
            "${
              ./config/wazuh_cluster/wazuh_manager.conf
            }:/wazuh-config-mount/etc/ossec.conf"
          ];
        };

        wazuh-indexer = {
          hostname = wazuh.indexer.hostname;
          image = "wazuh/wazuh-indexer:${version}";
          imageFile = wazuh.indexer.image;
          autoStart = true;
          extraOptions = [ "--network=host" "--ulimit" "nofile=65536:65536" ]
            ++ ulimits;
          dependsOn = [ ];
          environment = { OPENSEARCH_JAVA_OPTS = "-Xms1g -Xmx1g"; };
          ports = [ "9200:9200" ];
          volumes = [
            "wazuh-indexer-data:/var/lib/wazuh-indexer"
            "${
              ./config/wazuh_indexer/wazuh.indexer.yml
            }:/usr/share/wazuh-indexer/opensearch.yml"
            "${
              ./config/wazuh_indexer/internal_users.yml
            }:/usr/share/wazuh-indexer/opensearch-security/internal_users.yml"
          ];
        };

        wazuh-dashboard = {
          hostname = wazuh.dashboard.hostname;
          image = "wazuh/wazuh-dashboard:${version}";
          imageFile = wazuh.dashboard.image;
          autoStart = true;
          ports = [ "443:5601" ];
          environment = {
            INDEXER_USERNAME = config.programs.wazuh.indexerUsername;
            INDEXER_PASSWORD = config.programs.wazuh.indexerPassword;
            WAZUH_API_URL = "https://${wazuh.manager.hostname}";
            DASHBOARD_USERNAME = config.programs.wazuh.dashboardUsername;
            DASHBOARD_PASSWORD = config.programs.wazuh.dashboardPassword;
            API_USERNAME = config.programs.wazuh.apiUsername;
            API_PASSWORD = config.programs.wazuh.apiPassword;
          };
          extraOptions = [ "--network=host" ];
          dependsOn = [ "wazuh-indexer" ];
          volumes = [
            "${
              ./config/wazuh_dashboard/opensearch_dashboards.yml
            }:/usr/share/wazuh-dashboard/config/opensearch_dashboards.yml"
            "${
              ./config/wazuh_dashboard/wazuh.yml
            }:/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml"
            "wazuh-dashboard-config:/usr/share/wazuh-dashboard/data/wazuh/config"
            "wazuh-dashboard-custom:/usr/share/wazuh-dashboard/plugins/wazuh/public/assets/custom"
          ];
        };
      };
    };
  };
}

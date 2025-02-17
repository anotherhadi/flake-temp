{ pkgs, lib, config, ... }:
let
  certDir = "/var/lib/wazuh-certificates";

  generateCertsScript = pkgs.writeShellScriptBin "generate-wazuh-certs" ''
    set -e

    mkdir -p ${certDir}
    cd ${certDir}

    days_valid=3650

    # Fonction pour générer un certificat signé par la CA
    generate_cert() {
        local name=$1
        ${pkgs.openssl}/bin/openssl genrsa -out "$name-key.pem" 2048
        ${pkgs.openssl}/bin/openssl req -new -key "$name-key.pem" -out "$name.csr" -subj "/C=FR/ST=Paris/L=Paris/O=Wazuh/OU=$name/CN=$name"
        ${pkgs.openssl}/bin/openssl x509 -req -in "$name.csr" -CA root-ca.pem -CAkey root-ca.key -CAcreateserial -out "$name.pem" -days "$days_valid" -sha256
        rm "$name.csr"
    }


    # Générer l'autorité de certification (CA)
    if [ ! -f root-ca.pem ]; then
      ${pkgs.openssl}/bin/openssl genrsa -out root-ca.key 4096
      ${pkgs.openssl}/bin/openssl req -x509 -new -nodes -key root-ca.key -sha256 -days "$days_valid" -out root-ca.pem -subj "/C=FR/ST=Paris/L=Paris/O=Wazuh/OU=Security/CN=root-ca"

      # Génération des certificats pour les composants Wazuh
      generate_cert "wazuh.indexer"
      generate_cert "admin"
      cp root-ca.pem root-ca-manager.pem
      generate_cert "wazuh.manager"
      generate_cert "wazuh.dashboard"
    fi

  '';

in {
  # Ajouter une option pour activer la génération des certificats
  options.programs.wazuh.generateCerts = lib.mkOption {
    type = lib.types.bool;
    default = true;
    description = "Generate certificates";
  };

  config = lib.mkIf config.programs.wazuh.generateCerts {

    systemd.services.generate-wazuh-certs = {
      description = "Generate Wazuh SSL Certificates";
      after = [ "network.target" ];
      before = [ "docker.service" ]; # Générer les certificats avant Docker
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${generateCertsScript}/bin/generate-wazuh-certs";
        RemainAfterExit = true;
      };
    };

    # Modifier les volumes pour utiliser les certificats générés
    virtualisation.oci-containers.containers.wazuh-manager.volumes = [
      "${certDir}/root-ca.pem:/etc/ssl/root-ca.pem"
      "${certDir}/wazuh.manager.pem:/etc/ssl/filebeat.pem"
      "${certDir}/wazuh.manager-key.pem:/etc/ssl/filebeat.key"
    ];

    virtualisation.oci-containers.containers.wazuh-indexer.volumes = [
      "${certDir}/root-ca.pem:/usr/share/wazuh-indexer/certs/root-ca.pem"
      "${certDir}/wazuh.indexer-key.pem:/usr/share/wazuh-indexer/certs/wazuh.indexer.key"
      "${certDir}/wazuh.indexer.pem:/usr/share/wazuh-indexer/certs/wazuh.indexer.pem"
      "${certDir}/admin.pem:/usr/share/wazuh-indexer/certs/admin.pem"
      "${certDir}/admin-key.pem:/usr/share/wazuh-indexer/certs/admin-key.pem"
    ];

    virtualisation.oci-containers.containers.wazuh-dashboard.volumes = [
      "${certDir}/wazuh.dashboard.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard.pem"
      "${certDir}/wazuh.dashboard-key.pem:/usr/share/wazuh-dashboard/certs/wazuh-dashboard-key.pem"
      "${certDir}/root-ca.pem:/usr/share/wazuh-dashboard/certs/root-ca.pem"
    ];
  };
}

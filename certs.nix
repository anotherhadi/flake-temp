{ pkgs, lib, config, ... }:
let
  certDir = "/var/lib/wazuh-certificates";

  generateCertsScript = pkgs.writeShellScriptBin "generate-wazuh-certs" ''
    set -e

    mkdir -p ${certDir}
    cd ${certDir}

    # Générer l'autorité de certification (CA)
    if [ ! -f root-ca.pem ]; then
      openssl genrsa -out root-ca.key 2048
      openssl req -x509 -new -nodes -key root-ca.key -sha256 -days 3650 -out root-ca.pem -subj "/CN=Wazuh Root CA"
    fi

    # Fonction pour générer un certificat signé par la CA
    generate_cert() {
      local name=$1
      local keyfile="$name-key.pem"
      local csrfile="$name.csr"
      local certfile="$name.pem"

      if [ ! -f "$certfile" ]; then
        openssl genrsa -out $keyfile 2048
        openssl req -new -key $keyfile -out $csrfile -subj "/CN=$name"
        openssl x509 -req -in $csrfile -CA root-ca.pem -CAkey root-ca.key -CAcreateserial -out $certfile -days 3650 -sha256
      fi
    }

    # Génération des certificats pour les composants Wazuh
    generate_cert "wazuh.manager"
    generate_cert "wazuh.indexer"
    generate_cert "wazuh.dashboard"
    generate_cert "admin"
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

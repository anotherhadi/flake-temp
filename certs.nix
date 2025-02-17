{ pkgs, lib, config, ... }:
let
  certDir = "/etc/wazuh/config/wazuh_indexer_ssl_certs";

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
        # DEBUG
        chmod 644 "$name.pem"
        chmod 644 "$name-key.pem"
    }

    # Générer l'autorité de certification (CA)
    if [ ! -f root-ca.pem ]; then
      ${pkgs.openssl}/bin/openssl genrsa -out root-ca.key 4096
      ${pkgs.openssl}/bin/openssl req -x509 -new -nodes -key root-ca.key -sha256 -days "$days_valid" -out root-ca.pem -subj "/C=FR/ST=Paris/L=Paris/O=Wazuh/OU=Security/CN=root-ca"

      # Génération des certificats pour les composants Wazuh
      generate_cert "wazuh.indexer"
      generate_cert "admin"
      cp root-ca.pem root-ca-manager.pem
      cp root-ca.key root-ca-manager.key
      generate_cert "wazuh.manager"
      generate_cert "wazuh.dashboard"
    fi
    exit 0

  '';

in {
  # Ajouter une option pour activer la génération des certificats
  options.programs.wazuh.generateCerts = lib.mkOption {
    type = lib.types.bool;
    default = true;
    description = "Generate certificates";
  };

  config = lib.mkIf config.programs.wazuh.generateCerts {
    systemd.services.wazuh-certs = {
      description = "Generate Wazuh SSL Certificates";
      after = [ "network.target" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${generateCertsScript}/bin/generate-wazuh-certs";
        RemainAfterExit = true;
      };
    };
  };
}

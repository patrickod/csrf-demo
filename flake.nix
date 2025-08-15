{
  description = "CSRF Demo - Cross-Site Request Forgery demonstration application";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        csrfDemo = pkgs.buildGoModule {
          pname = "csrf-demo";
          version = "0.1.0";

          src = ./.;

          vendorHash = "sha256-Nn0Nk5ht0erfeFv7G+gAS3S/tJkA88TKZwB7Xh61X74=";

          ldflags = [ "-s" "-w" ];

          meta = with pkgs.lib; {
            description = "Cross-Site Request Forgery demonstration application";
            homepage = "https://github.com/patrickod/csrf-demo";
            license = licenses.mit;
            maintainers = [ ];
          };
        };
      in
      {
        packages = {
          default = csrfDemo;
          csrf-demo = csrfDemo;
        };

        apps = {
          default = flake-utils.lib.mkApp {
            drv = csrfDemo;
          };
        };

        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            go
          ];
        };
      }
    ) // {
      nixosModules.default = { config, lib, pkgs, ... }:
        with lib;
        let
          cfg = config.services.csrf-demo;
          pkg = self.packages.${pkgs.system}.csrf-demo;
        in
        {
          options.services.csrf-demo = {
            enable = mkEnableOption "CSRF Demo application";

            port = mkOption {
              type = types.port;
              default = 8080;
              description = "Port to listen on for HTTP requests";
            };

            debugPort = mkOption {
              type = types.port;
              default = 8081;
              description = "Port to listen on for debug interface";
            };

            listenAddress = mkOption {
              type = types.str;
              default = "127.0.0.1";
              description = "Address to listen on";
            };

            domain = mkOption {
              type = types.str;
              default = "csrf.example.com";
              description = "Domain to use for the demo";
            };

            user = mkOption {
              type = types.str;
              default = "csrf-demo";
              description = "User to run the service as";
            };

            group = mkOption {
              type = types.str;
              default = "csrf-demo";
              description = "Group to run the service as";
            };
          };

          config = mkIf cfg.enable {
            users.users.${cfg.user} = {
              isSystemUser = true;
              group = cfg.group;
              home = "/var/lib/csrf-demo";
              createHome = true;
              homeMode = "750";
            };

            users.groups.${cfg.group} = {};

            systemd.services.csrf-demo = {
              description = "CSRF Demo Application";
              wantedBy = [ "multi-user.target" ];
              after = [ "network.target" ];

              serviceConfig = {
                Type = "simple";
                User = cfg.user;
                Group = cfg.group;
                WorkingDirectory = "/var/lib/csrf-demo";
                ExecStart = "${pkg}/bin/csrf-demo -listen=${cfg.listenAddress}:${toString cfg.port} -domain=${cfg.domain}";
                Restart = "always";
                RestartSec = "10s";

                # Security settings
                NoNewPrivileges = true;
                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                PrivateDevices = true;
                ProtectHostname = true;
                ProtectClock = true;
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectKernelLogs = true;
                ProtectControlGroups = true;
                RestrictAddressFamilies = [ "AF_UNIX" "AF_INET" "AF_INET6" ];
                RestrictNamespaces = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                RemoveIPC = true;

                # Allow writing to working directory
                ReadWritePaths = [ "/var/lib/csrf-demo" ];
              };

              environment = {
                HOME = "/var/lib/csrf-demo";
              };
            };

            # Ensure the data directory has correct permissions
            systemd.tmpfiles.rules = [
              "d '/var/lib/csrf-demo' 0750 ${cfg.user} ${cfg.group} - -"
            ];
          };
        };
    };
}

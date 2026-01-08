{
  description = "Fuzzy find and kill processes from your terminal";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };
      in
      {
        # Build dependenxies for rust project
        packages = rec {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "rip-cli";
            version = "0.1.0";
            src = ./.; # flake location

            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            nativeBuildInputs = with pkgs; [
              pkg-config
            ];

            buildInputs =
              with pkgs;
              [ ]
              ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
                pkgs.darwin.apple_sdk.frameworks.Security
                pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
              ];

            # Metadata shown in nix
            meta = with pkgs.lib; {
              description = "Fuzzy find and kill processes from your terminal";
              homepage = "https://github.com/MaySeikatsu/rip";
              license = licenses.mit;
              maintainers = [ ];
              mainProgram = "rip";
            };
          };

          # To be able to reference it as rip instead of default - kinda like an alias
          rip = self.packages.${system}.default;
        };

        # Execute with `nix run github:MaySeikatsu/rip`
        apps = {
          default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/rip";
          };
        };

        # DevTools if wanted to be exectued with nix develop
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc
            cargo
            rust-analyzer
            rustfmt
            clippy
          ];
        };
      }
    );
}


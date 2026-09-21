{
  inputs = {
    llzk-pkgs.url = "github:project-llzk/llzk-nix-pkgs";
    nixpkgs.follows = "llzk-pkgs/nixpkgs";
    flake-utils.follows = "llzk-pkgs/flake-utils";
    llzk-rs-pkgs = {
      url = "github:project-llzk/llzk-rs";
      inputs = {
        nixpkgs.follows = "llzk-pkgs/nixpkgs";
        flake-utils.follows = "llzk-pkgs/flake-utils";
        llzk-pkgs.follows = "llzk-pkgs";
      };
    };
    llzk-lib.follows = "llzk-rs-pkgs/llzk-lib";
    release-helpers.follows = "llzk-rs-pkgs/llzk-lib/release-helpers";
    rust-overlay.follows = "llzk-rs-pkgs/rust-overlay";
  };

  # Custom colored bash prompt
  nixConfig.bash-prompt = "\\[\\e[0;32m\\][haloumi]\\[\\e[m\\] \\[\\e[38;5;244m\\]\\w\\[\\e[m\\] % ";

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      release-helpers,
      llzk-pkgs,
      llzk-lib,
      llzk-rs-pkgs,
      rust-overlay,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            (import rust-overlay)
            llzk-pkgs.overlays.default
            llzk-lib.overlays.default
            llzk-rs-pkgs.overlays.default
            release-helpers.overlays.default
          ];
        };

        haloumi = pkgs.rustPlatform.buildRustPackage (
          {
            pname = "haloumi";
            version = "0.5.12";
            src = ./.;

            nativeBuildInputs = pkgs.llzkSharedEnvironment.nativeBuildInputs;
            buildInputs = pkgs.llzkSharedEnvironment.devBuildInputs;

            cargoLock = {
              lockFile = ./Cargo.lock;
              allowBuiltinFetchGit = true;
            };

            cargoBuildFlags = [
              "--package"
              "haloumi"
            ];
            cargoTestFlags = [
              "--package"
              "haloumi"
            ];
            dontUsePytestCheck = true;
          }
          // pkgs.llzkSharedEnvironment.env
          // pkgs.llzkSharedEnvironment.pkgSettings
        );
      in
      {
        packages = flake-utils.lib.flattenTree {
          haloumi = haloumi;
          default = haloumi;
        };

        devShells = flake-utils.lib.flattenTree {
          default = pkgs.mkShell (
            {
              nativeBuildInputs = pkgs.llzkSharedEnvironment.nativeBuildInputs;
              buildInputs = pkgs.llzkSharedEnvironment.devBuildInputs ++ [
                pkgs.nixfmt-rfc-style
                pkgs.rust-bin.stable.latest.default
              ];
            }
            // pkgs.llzkSharedEnvironment.env
            // pkgs.llzkSharedEnvironment.devSettings
          );
          nightly = pkgs.mkShell (
            {
              nativeBuildInputs = pkgs.llzkSharedEnvironment.nativeBuildInputs;
              buildInputs = pkgs.llzkSharedEnvironment.devBuildInputs ++ [
                pkgs.rust-bin.nightly.latest.default
              ];
            }
            // pkgs.llzkSharedEnvironment.env
            // pkgs.llzkSharedEnvironment.devSettings
          );
        };
      }
    );
}

{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs?rev=fa804edfb7869c9fb230e174182a8a1a7e512c40";
    utils.url = "github:numtide/flake-utils";
    fenix.url = "github:nix-community/fenix";
    fenix.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, utils, fenix }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        rust-toolchain = with fenix.packages.${system};
          combine (with complete; [
            rustc
            rust-src
            cargo
            clippy
            rustfmt
            rust-analyzer
          ]);
      in
      {
        devShell = with pkgs; mkShell rec {
          buildInputs = [
            rust-toolchain
            gnumake
            linuxPackages_zen.kernel.dev
          ];

          KERNEL_PATH = "${linuxPackages_zen.kernel.dev}";
        };
      }
    );
}

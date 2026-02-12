{
  description = "Aya description";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
    eunomia-bpf.url = "github:eunomia-bpf/eunomia-bpf";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, eunomia-bpf }:
      flake-utils.lib.eachSystem
      (with flake-utils.lib.system; [ x86_64-linux ])
      (system: 
        let
          overlays = [ (import rust-overlay) ];
          pkgs = import nixpkgs { inherit system overlays; };
          eunomia-pkgs = eunomia-bpf.packages.${system};
          # bpf-linker has a hard requirement on llvm 21
          llvmPackages = pkgs.llvmPackages_21;
          bpftool = pkgs.runCommand "bpftool" {} ''
            mkdir -p $out/bin
            cp ${eunomia-pkgs.bpftool}/src/bpftool $out/bin
          '';
          # this specific rust version is built on llvm 21, DO NOT blindly upgrade
          # or ebpf compilation will break
          rust-toolchain = pkgs.rust-bin.nightly."2025-12-15".default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
            ];
            targets = [
              "wasm32-unknown-unknown"
            ];
          };

          rustfmt = pkgs.rust-bin.stable.latest.rustfmt;

          rustPlatform = pkgs.makeRustPlatform {
            cargo = rust-toolchain;
            rustc = rust-toolchain;
          };

          bindgen = rustPlatform.buildRustPackage rec {
            pname = "bindgen-cli";
            version = "v0.72.1";
            src = pkgs.fetchFromGitHub {
              owner = "rust-lang";
              repo = "rust-bindgen";
              rev = "27577d2930af9311495b0d0f016f903824521ddc";
              sha256 = "sha256-cswBbshxTAcZtUk3PxH9jD55X1a/fBAyZyYpzVkt27M=";
            };

            cargoLock = {
              lockFile = "${src}/Cargo.lock";
            };

            nativeBuildInputs = [ pkgs.pkg-config ];

            buildInputs = [ pkgs.openssl ];

            doCheck = false;
          };
        in
    {
    devShells.default = pkgs.mkShell {
      packages = with pkgs; [
        clang
        openssl
        pkg-config
        binaryen # wasm tools
        bpf-linker
        wasmtime # for 'wasmtime explore' command mostly
      ] ++ [
        bpftool
        rust-toolchain
        bindgen
        rustfmt
      ];

      shellHook = ''
        export LIBCLANG_PATH=${llvmPackages.libclang.lib}/lib
      '';
    };
  });
}

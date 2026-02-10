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
          bpftool = pkgs.runCommand "bpftool" {} ''
            mkdir -p $out/bin
            cp ${eunomia-pkgs.bpftool}/src/bpftool $out/bin
          '';
          rust-toolchain = pkgs.rust-bin.nightly.latest.default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
            ];
            targets = [
              # "wasm32-unknown-unknown"
              # "bpfel-unknown-none"
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
              rev = "27577d2930af9311495b0d0f016f903824521ddc"; # v0.72.1
              sha256 = "sha256-cswBbshxTAcZtUk3PxH9jD55X1a/fBAyZyYpzVkt27M=";
            };

            cargoLock = {
              lockFile = "${src}/Cargo.lock";
            };

            nativeBuildInputs = [ pkgs.pkg-config ];

            buildInputs = [ pkgs.openssl ];

            doCheck = false;
          };

          bpf-linker = rustPlatform.buildRustPackage rec {
            pname = "bpf-linker";
            version = "0.10.1";

            src = pkgs.fetchFromGitHub {
              owner = "aya-rs";
              repo = "bpf-linker";
              tag = "v${version}";
              hash = "sha256-WFMQlaM18v5FsrsjmAl1nPGNMnBW3pjXmkfOfv3Izq0=";
            };

            cargoHash = "sha256-coIcd6WjVQM/b51jwkG8It/wubXx6wuuPlzzelPFBBB=";

            buildNoDefaultFeatures = true;
            buildFeatures = [ "llvm-${pkgs.lib.versions.major pkgs.rustc.llvm.version}" ];

            nativeBuildInputs = [ pkgs.rustc.llvm ];

            buildInputs = with pkgs; [
              zlib
              libxml2
            ];

            nativeCheckInputs = with pkgs; [
              btfdump
              rustc.llvmPackages.clang.cc
            ];
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
      ] ++ [
        bpftool
        rust-toolchain
        bindgen
        rustfmt
      ];

      shellHook = ''
        export LIBCLANG_PATH=${pkgs.llvmPackages_21.libclang.lib}/lib
      '';
    };
  });
}

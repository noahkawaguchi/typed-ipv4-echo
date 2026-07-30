{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { nixpkgs, rust-overlay, ... }:
    {
      devShells = nixpkgs.lib.genAttrs [ "aarch64-linux" "x86_64-linux" ] (
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              # Use nightly for formatting only
              rust-bin.nightly.latest.rustfmt
              (rust-bin.stable."1.97.1".minimal.override {
                extensions = [
                  "rust-src"
                  "rust-analyzer"
                  "clippy"
                  "llvm-tools-preview"
                ];
                targets = [
                  "aarch64-unknown-linux-gnu"
                  "x86_64-unknown-linux-gnu"
                ];
              })

              cargo-llvm-cov
              codebook
              inetutils
              just
              tshark
            ];

            # If using a dumpcap wrapper, make it take precedence
            shellHook = ''
              if [ -e /run/wrappers/bin/dumpcap ]; then export PATH="/run/wrappers/bin:$PATH"; fi
            '';
          };
        }
      );
    };
}

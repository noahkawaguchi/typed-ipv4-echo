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
          overlays = [ rust-overlay.overlays.default ];
          pkgs = import nixpkgs { inherit system overlays; };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              # Use nightly for formatting only
              rust-bin.nightly.latest.rustfmt
              (rust-bin.stable."1.96.0".minimal.override {
                extensions = [
                  "rust-src"
                  "rust-analyzer"
                  "clippy"
                ];
                targets = [
                  "aarch64-unknown-linux-gnu"
                  "x86_64-unknown-linux-gnu"
                ];
              })

              inetutils
              just
            ];
          };
        }
      );
    };
}

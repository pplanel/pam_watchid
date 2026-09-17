{
  description = "PAM module for authenticating with Apple Watch";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs = {
    self,
    nixpkgs,
  }: let
    systems = ["aarch64-darwin" "x86_64-darwin"];
    forAllSystems = nixpkgs.lib.genAttrs systems;
  in {
    packages = forAllSystems (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      apple-sdk = pkgs.apple-sdk_26 or pkgs.apple-sdk_15 or pkgs.apple-sdk;
    in {
      default = pkgs.callPackage ./default.nix { inherit apple-sdk; };
      pam-watchid = pkgs.callPackage ./default.nix { inherit apple-sdk; };
    });

    overlays.default = final: prev: {
      pam-watchid = prev.callPackage ./default.nix {
        apple-sdk = prev.apple-sdk_26 or prev.apple-sdk_15 or prev.apple-sdk;
      };
    };
  };
}

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
    in {
      default = pkgs.callPackage ./default.nix {};
      pam-watchid = pkgs.callPackage ./default.nix {};
    });

    overlays.default = final: prev: {
      pam-watchid = prev.callPackage ./default.nix {};
    };
  };
}

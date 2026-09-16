{
  pkgs ? import <nixpkgs> {},
  lib ? pkgs.lib,
  stdenv ? pkgs.stdenv,
  apple-sdk ? pkgs.apple-sdk_26 or pkgs.apple-sdk_15 or pkgs.apple-sdk or null,
  openpam ? pkgs.openpam,
}:

stdenv.mkDerivation {
  pname = "pam-watchid";
  version = "2026-09-16";

  src = lib.cleanSourceWith {
    src = lib.cleanSource ./.;
    filter = name: type:
      let
        base = baseNameOf (toString name);
      in
        base != "build" && base != ".git" && base != "result";
  };

  buildInputs = [
    apple-sdk
    openpam
  ];

  buildPhase = ''
    runHook preBuild
    mkdir -p build
    $CC -fobjc-arc -O2 -Wall -Wextra -mmacosx-version-min=15.0 \
      -dynamiclib \
      -Wl,-install_name,pam_watchid.so \
      -lpam \
      -framework Foundation -framework LocalAuthentication -framework SystemConfiguration \
      -o build/pam_watchid.so src/pam_watchid.m
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -d -m 755 $out/lib/pam
    install -m 444 build/pam_watchid.so $out/lib/pam/pam_watchid.so
    runHook postInstall
  '';

  meta = with lib; {
    description = "PAM module for authenticating with Apple Watch";
    homepage = "https://github.com/pplanel/pam_watchid";
    license = licenses.mit;
    platforms = platforms.darwin;
  };
}

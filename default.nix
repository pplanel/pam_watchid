{
  pkgs ? import <nixpkgs> {},
  lib ? pkgs.lib,
  stdenv ? pkgs.stdenv,
  apple-sdk ? pkgs.apple-sdk_26 or pkgs.apple-sdk_15 or pkgs.apple-sdk or null,
  apple-sdk_26 ? pkgs.apple-sdk_26 or null,
  apple-sdk_15 ? pkgs.apple-sdk_15 or null,
  openpam ? pkgs.openpam,
}:

let
  sdk =
    if (apple-sdk != null && apple-sdk ? version && lib.versionAtLeast apple-sdk.version "15.0") then
      apple-sdk
    else if apple-sdk_26 != null then
      apple-sdk_26
    else if apple-sdk_15 != null then
      apple-sdk_15
    else
      apple-sdk;
in
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
    sdk
    openpam
  ];

  buildPhase = ''
    runHook preBuild
    mkdir -p build
    $CC -fobjc-arc -O2 -Wall -Wextra -mmacosx-version-min=15.0 \
      -bundle -undefined dynamic_lookup \
      -Wl,-install_name,pam_watchid.so \
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

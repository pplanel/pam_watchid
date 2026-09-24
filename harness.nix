{
  pkgs ? import <nixpkgs> {},
  lib ? pkgs.lib,
  stdenv ? pkgs.stdenv,
  apple-sdk ? pkgs.apple-sdk_26 or pkgs.apple-sdk_15 or pkgs.apple-sdk or null,
  openpam ? pkgs.openpam,
  pam-watchid,          # required — must come from the pam-watchid derivation
}:

stdenv.mkDerivation {
  pname = "pam-watchid-harness";
  version = pam-watchid.version;

  src = lib.cleanSourceWith {
    src = lib.cleanSource ./.;
    filter = name: _type:
      let base = baseNameOf (toString name);
      in base != "build" && base != ".git" && base != "result";
  };

  buildInputs = [
    apple-sdk
    openpam
  ];

  buildPhase = ''
    runHook preBuild
    mkdir -p build
    $CC -fobjc-arc -O2 -Wall -Wextra -mmacosx-version-min=15.0 \
      -framework Foundation \
      -o build/harness test/harness.m
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    install -d -m 755 $out/bin

    # The harness hard-codes "build/pam_watchid.so" as the module path.
    # Wrap it with a small shell launcher that places a symlink to the
    # Nix store copy in the working directory's build/ sub-directory so
    # dlopen("build/pam_watchid.so") resolves correctly wherever the
    # user invokes the wrapper from.
    install -m 555 build/harness $out/bin/.harness-unwrapped

    cat > $out/bin/pam-watchid-harness <<'EOF'
    #!/bin/sh
    set -e
    MODULE="${pam-watchid}/lib/pam/pam_watchid.so"
    if [ ! -f "$MODULE" ]; then
      echo "pam-watchid module not found: $MODULE" >&2
      exit 1
    fi
    TMPDIR=$(mktemp -d)
    trap 'rm -rf "$TMPDIR"' EXIT
    mkdir -p "$TMPDIR/build"
    ln -s "$MODULE" "$TMPDIR/build/pam_watchid.so"
    cd "$TMPDIR"
    exec ${placeholder "out"}/bin/.harness-unwrapped "$@"
    EOF
    chmod 555 $out/bin/pam-watchid-harness

    runHook postInstall
  '';

  meta = with lib; {
    description = "Standalone test harness for pam-watchid (zero-risk, no system PAM changes)";
    homepage    = "https://github.com/pplanel/pam_watchid";
    license     = licenses.mit;
    platforms   = platforms.darwin;
    mainProgram = "pam-watchid-harness";
  };
}

final: prev: {
  pam-watchid = prev.stdenv.mkDerivation rec {
    pname = "pam-watchid";
    version = "2026-09-16";

    src = prev.fetchFromGitHub {
      owner = "pplanel";
      repo = "pam_watchid";
      rev = "50acb6f355ba388e4488164300ed8734c4351894";
      hash = "sha256-OgL6aM2vZQU2NiQgX8gWe74WcuQWxa3TjFMZ/g4E4L8=";
    };

    buildInputs = [
      (prev.apple-sdk_26 or prev.apple-sdk_15 or prev.apple-sdk)
      prev.openpam
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

    meta = with prev.lib; {
      description = "PAM module for authenticating with Apple Watch";
      homepage = "https://github.com/pplanel/pam_watchid";
      license = licenses.mit;
      platforms = platforms.darwin;
    };
  };
}

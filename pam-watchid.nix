final: prev: {
  pam-watchid = prev.stdenv.mkDerivation rec {
    pname = "pam-watchid";
    version = "2026-09-16";

    src = prev.fetchFromGitHub {
      owner = "pplanel";
      repo = "pam_watchid";
      rev = "d7f7193013b7774fe4db95f07b577ffb6edd7510";
      hash = "sha256-8z23aYlBF+aQaAnP8NyAviEpTUx2wln/sdRte5P3gs4=";
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

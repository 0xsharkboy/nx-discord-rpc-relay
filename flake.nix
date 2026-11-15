{
  description = "nx-discord-rpc relay server";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        sdkLibs = with pkgs; [ alsa-lib libpulseaudio libx11 ];
      in {
        devShells.default = pkgs.mkShell {
          packages = (with pkgs; [
            cmake ninja gcc pkg-config sqlite openssl git clang-tools
          ]) ++ sdkLibs;

          CMAKE_EXPORT_COMPILE_COMMANDS = "ON";
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath (sdkLibs ++ [ pkgs.stdenv.cc.cc.lib ]);
        };
      });
}

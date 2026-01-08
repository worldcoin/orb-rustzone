{
  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.orb-software = {
    url = "github:worldcoin/orb-software";
    inputs.seekSdk.url = "path:./empty";
  };

  outputs =
    {
      self,
      flake-utils,
      nixpkgs,
      orb-software,
      ...
    }:
    # Now eachDefaultSystem is only using ["x86_64-linux"], but this list can also
    # further be changed by users of your flake.
    flake-utils.lib.eachDefaultSystem (system: {
      devShells.default = orb-software.devShells.${system}.default;
    });
}

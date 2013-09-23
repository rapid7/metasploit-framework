# The states that a host can be in.
module Msf::HostState
  #
  # The host is alive.
  #
  Alive   = "alive"
  #
  # The host is dead.
  #
  Dead    = "down"
  #
  # The host state is unknown.
  #
  Unknown = "unknown"
end
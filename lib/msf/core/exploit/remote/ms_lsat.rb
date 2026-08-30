###
#
# This mixin provides methods to look-up security identifiers on the remote SMB server.
#
# -*- coding: binary -*-

module Msf

  module Exploit::Remote::MsLsat

    def lookup_sids(policy_handle, sids, lookup_level)
      sids = [sids] unless sids.is_a?(Array)

      self.lsarpc_pipe.lsar_lookup_sids(
        policy_handle: policy_handle,
        sids: sids,
        lookup_level: lookup_level
      )
    end

  end
end

# -*- coding: binary -*-

require 'rex/exploitation/vbsobfuscate'

module Msf
  # VBS obfuscation library wrapper for Rex::Exploitation::VBSObfuscate
  module Exploit::VBSObfuscate
    def initialize(info = {})
      super
      register_advanced_options([
        OptInt.new('VbsObfuscate', [false, 'Number of times to obfuscate VBS', 1]),
      ])
    end

    #
    # Returns an VBSObfuscate object. A wrapper of ::Rex::Exploitation::VBSObfuscate.new(vbs).obfuscate!
    #
    # @param vbs [String] VBS code
    # @param opts [Hash] obfuscation options
    #    * :iterations [FixNum] Number of times to obfuscate
    #    * :normalize_whitespace [Boolean] normalize line endings and strip leading/trailing whitespace from each line (true)
    #    * :dynamic_execution [Boolean] dynamically execute obfuscated code with Execute (true)
    # @return [::Rex::Exploitation::VBSObfuscate]
    #
    def vbs_obfuscate(vbs, opts = {})
      iterations = (opts[:iterations] || datastore['VbsObfuscate']).to_i
      normalize_whitespace = opts[:normalize_whitespace].blank? || opts[:normalize_whitespace]
      dynamic_execution = opts[:dynamic_execution].blank? || opts[:dynamic_execution]

      vbs_obfuscate = ::Rex::Exploitation::VBSObfuscate.new(vbs)
      vbs_obfuscate.obfuscate!(
        iterations: iterations,
        normalize_whitespace: normalize_whitespace,
        dynamic_execution: dynamic_execution
      )
      vbs_obfuscate
    end
  end
end

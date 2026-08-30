# -*- coding: binary -*-

require 'rex/exploitation/jsobfu'

module Msf
  module Exploit::JSObfu

    def initialize(info={})
      super
      register_advanced_options([
        OptInt.new('JsObfuscate', [false, "Number of times to obfuscate JavaScript", 0]),
        OptString.new('JsIdentifiers', [false, "Identifiers to preserve for JsObfu"])
      ], Exploit::JSObfu)
    end

    #
    # Returns an JSObfu object. A wrapper of ::Rex::Exploitation::JSObfu.new(js).obfuscate
    #
    # @param js [String] JavaScript code
    # @param opts [Hash] obfuscation options
    #    * :iterations [FixNum] Number of times to obfuscate
    #    * :preserved_identifiers [Array] An array of identifiers to preserve during obfuscation
    # @return [::Rex::Exploitation::JSObfu]
    #
    def js_obfuscate(js, opts={})
      iterations = (opts[:iterations] || datastore['JsObfuscate']).to_i
      identifiers = opts[:preserved_identifiers].blank? ? (datastore['JsIdentifiers'] || '').split(',') : opts[:preserved_identifiers]
      obfu = ::Rex::Exploitation::JSObfu.new(js)
      obfu_opts = {}
      obfu_opts.merge!(iterations: iterations)
      obfu_opts.merge!(preserved_identifiers: identifiers)

      obfu.obfuscate(obfu_opts)
      obfu
    end

  end
end

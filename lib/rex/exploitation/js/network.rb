# -*- coding: binary -*-

require 'msf/core'

module Rex
module Exploitation
module Js

#
# Provides networking functions in JavaScript
#
class Network

  # @param [Hash] opts the options hash
  # @option opts [Boolean] :obfuscate toggles js obfuscation. defaults to true.
  # @option opts [Boolean] :inject_xhr_shim automatically stubs XHR to use ActiveXObject when needed.
  #   defaults to true.
  # @return [String] javascript code to perform a synchronous ajax request to the remote
  #   and returns the response
  def self.ajax_download(opts={})
    should_obfuscate = opts.fetch(:obfuscate, true)
    js = ::File.read(::File.join(Msf::Config.data_directory, "js", "network", "ajax_download.js"))

    if should_obfuscate
      js = ::Rex::Exploitation::ObfuscateJS.new(js,
        {
          'Symbols' => {
            'Variables' => %w{ xmlHttp oArg }
          }
      }).obfuscate
    end

    xhr_shim(opts) + js
  end

  # @param [Hash] opts the options hash
  # @option opts [Boolean] :obfuscate toggles js obfuscation. defaults to true.
  # @option opts [Boolean] :inject_xhr_shim automatically stubs XHR to use ActiveXObject when needed.
  #   defaults to true.
  # @return [String] javascript code to perform a synchronous or asynchronous ajax request to
  #   the remote with the data specified.
  def self.ajax_post(opts={})
    should_obfuscate = opts.fetch(:obfuscate, true)
    js = ::File.read(::File.join(Msf::Config.data_directory, "js", "network", "ajax_post.js"))

    if should_obfuscate
      js = ::Rex::Exploitation::ObfuscateJS.new(js,
        {
          'Symbols' => {
            'Variables' => %w{ xmlHttp cb path data }
          }
        }).obfuscate
    end

    xhr_shim(opts) + js
  end

  # @param [Hash] opts the options hash
  # @option opts [Boolean] :obfuscate toggles js obfuscation. defaults to true.
  # @option opts [Boolean] :inject_xhr_shim false causes this method to return ''. defaults to true.
  # @return [String] javascript code that adds XMLHttpRequest to the global scope if it
  #   does not exist (e.g. on IE6, where you have to use the ActiveXObject constructor)
  def self.xhr_shim(opts={})
    return '' unless opts.fetch(:inject_xhr_shim, true)

    should_obfuscate = opts.fetch(:obfuscate, true)
    js = ::File.read(::File.join(Msf::Config.data_directory, "js", "network", "xhr_shim.js"))

    if should_obfuscate
      js = ::Rex::Exploitation::ObfuscateJS.new(js,
        {
          'Symbols' => {
            'Variables' => %w{ activeObjs idx }
          }
        }
      ).obfuscate
    end
    js
  end

end
end
end
end

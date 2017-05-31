# -*- coding: binary -*-
require 'recog'

module Msf
  ###
  # This module provides methods for auxiliary modules that want to utilize Recog
  ###
  module Auxiliary::Recog
    def initialize(info = {})
      super
      register_advanced_options(
        [
          OptBool.new('ShowRecogResults', [true, 'Show Recog hits and misses', true]),
          OptBool.new('UseRecog', [true, 'Uses Recog to further fingerprint and report services', true])
        ], Auxiliary::Recog
      )
    end

    def report_recog_info(endpoint, type, banner)
      return unless datastore['UseRecog']
      sanitized_banner = Rex::Text.to_hex_ascii(banner)
      vprint_status("#{endpoint} checking for Recog #{type} match")
      recog_match = Recog::Nizer.match(type, banner)
      if recog_match
        if datastore['ShowRecogResults']
          print_status("#{endpoint} Recog #{type} match: #{sanitized_banner}")
        end
        # TODO: should we do this?  if so, how to unit test it?
        # report_service(host: rhost, port: 21, name: 'ftp', proto: 'tcp', info: banner)
      else
        if datastore['ShowRecogResults']
          print_warning("#{endpoint} no Recog #{type} match: #{sanitized_banner}")
        end
        # TODO: should we do this?  if so, how to unit test it?
        # report_service(host: rhost, port: 21, name: 'ftp', proto: 'tcp', info: banner)
      end
      recog_match
    end
  end
end

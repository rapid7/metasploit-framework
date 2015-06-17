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
          OptBool.new('ShowRecogResults', [true, 'Show Recog hits and misses', true])
        ], Auxiliary::Recog
      )
    end

    def recog_info(endpoint, type, banner)
      sanitized_banner = Rex::Text.to_hex_ascii(banner)
      vprint_status("#{endpoint} checking for Recog #{type} match")
      recog_match = Recog::Nizer.match(type, banner)
      if datastore['ShowRecogResults']
        if recog_match
          print_status("#{endpoint} Recog #{type} match: #{sanitized_banner}")
        else
          print_warning("#{endpoint} no Recog #{type} match: #{sanitized_banner}")
        end
      else
        print_status("#{endpoint} #{type}: '#{sanitized_banner}'")
      end
      recog_match
    end
  end
end

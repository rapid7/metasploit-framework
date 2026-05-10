# frozen_string_literal: true

require 'time'

module Msf::MCP
  module Metasploit
    # Transforms Metasploit RPC responses into MCP-compatible format
    # Adds metadata, converts field names, and formats timestamps
    class ResponseTransformer
      # Transform module search results
      # @param modules [Array<Hash>] Raw module data from Metasploit
      # @return [Array<Hash>] Transformed modules with MCP metadata
      def self.transform_modules(modules)
        return [] unless modules.is_a?(Array)

        modules.map do |mod|
          {
            name: mod['name'] || mod['fullname'],
            type: mod['type'],
            fullname: mod['fullname'],
            rank: mod['rank'],
            disclosure_date: mod['disclosuredate']
          }.compact
        end
      end

      # Transform module info response
      # @param info [Hash] Raw module info from Metasploit
      # @return [Hash] Transformed info with MCP metadata
      def self.transform_module_info(info)
        return {} unless info.is_a?(Hash)

        {
          type: info['type'],
          name: info['name'],
          fullname: info['fullname'],
          rank: info['rank'],
          disclosure_date: info['disclosuredate'],
          description: info['description'],
          license: info['license'],
          filepath: info['filepath']&.sub(/^.*modules\//, 'modules/'), # Dont expose the install path
          architectures: info['arch'],
          platforms: info['platform'],
          authors: info['authors'],
          privileged: info['privileged'],
          has_check_method: info['check'],
          # TODO: write transformer for default_options
          default_options: info['default_options'],
          references: transform_references(info['references']),
          targets: info['targets'],
          default_target: info['default_target'],
          stance: info['stance'],
          actions: info['actions'],
          default_action: info['default_action'],
          # TODO: write transformer for options
          options: info['options']
        }.compact
      end

      # Transform hosts response
      # @param response [Hash] Raw response with 'hosts' array
      # @return [Array<Hash>] Transformed hosts with MCP metadata
      def self.transform_hosts(response)
        return [] unless response.is_a?(Hash) && response['hosts'].is_a?(Array)

        response['hosts'].map do |host|
          {
            created_at: format_timestamp(host['created_at']),
            address: host['address'],
            mac_address: host['mac'],
            hostname: host['name'],
            state: host['state'],
            os_name: host['os_name'],
            os_flavor: host['os_flavor'],
            os_service_pack: host['os_sp'],
            os_language: host['os_lang'],
            updated_at: format_timestamp(host['updated_at']),
            purpose: host['purpose'],
            info: host['info']
          }.compact
        end
      end

      # Transform services response
      # @param response [Hash] Raw response with 'services' array
      # @return [Array<Hash>] Transformed services
      def self.transform_services(response)
        return [] unless response.is_a?(Hash) && response['services'].is_a?(Array)

        response['services'].map do |service|
          {
            host_address: service['host'],
            created_at: format_timestamp(service['created_at']),
            updated_at: format_timestamp(service['updated_at']),
            port: service['port'],
            protocol: service['proto'],
            state: service['state'],
            name: service['name'],
            info: service['info'],
          }.compact
        end
      end

      # Transform vulnerabilities response
      # @param response [Hash] Raw response with 'vulns' array
      # @return [Array<Hash>] Transformed vulnerabilities
      def self.transform_vulns(response)
        return [] unless response.is_a?(Hash) && response['vulns'].is_a?(Array)

        response['vulns'].map do |vuln|
          {
            host: vuln['host'],
            port: vuln['port'],
            protocol: vuln['proto'],
            name: vuln['name'],
            references: parse_refs(vuln['refs']),
            created_at: format_timestamp(vuln['time'])
          }.compact
        end
      end

      # Transform notes response
      # @param response [Hash] Raw response with 'notes' array
      # @return [Array<Hash>] Transformed notes
      def self.transform_notes(response)
        return [] unless response.is_a?(Hash) && response['notes'].is_a?(Array)

        response['notes'].map do |note|
          {
            host: note['host'],
            service_name_or_port: note['service'],
            note_type: note['type'] || note['ntype'],
            data: note['data'],
            created_at: format_timestamp(note['time'])
          }.compact
        end
      end

      # Transform credentials response
      # @param response [Hash] Raw response with 'creds' array
      # @return [Array<Hash>] Transformed credentials
      def self.transform_creds(response)
        return [] unless response.is_a?(Hash) && response['creds'].is_a?(Array)

        response['creds'].map do |cred|
          {
            host: cred['host'],
            port: cred['port'],
            protocol: cred['proto'],
            service_name: cred['sname'],
            user: cred['user'],
            secret: cred['pass'],
            type: cred['type'],
            updated_at: format_timestamp(cred['updated_at'])
          }.compact
        end
      end

      # Transform loot response
      # @param response [Hash] Raw response with 'loots' array
      # @return [Array<Hash>] Transformed loot
      def self.transform_loot(response)
        return [] unless response.is_a?(Hash) && response['loots'].is_a?(Array)

        response['loots'].map do |loot|
          {
            host: loot['host'],
            service_name_or_port: loot['service'],
            loot_type: loot['ltype'],
            content_type: loot['ctype'],
            name: loot['name'],
            info: loot['info'],
            data: loot['data'],
            created_at: format_timestamp(loot['created_at']),
            updated_at: format_timestamp(loot['updated_at'])
          }.compact
        end
      end

      private

      # Convert Unix epoch timestamp to ISO 8601 format
      # @param timestamp [Integer, nil] Unix timestamp
      # @return [String, nil] ISO 8601 formatted string
      def self.format_timestamp(timestamp)
        return nil if timestamp.nil? || timestamp.to_i.zero?
        Time.at(timestamp.to_i).utc.iso8601
      end

      # Transform references array
      # @param refs [Array, nil] References from Metasploit
      # @return [Array<Hash>, nil] Transformed references
      def self.transform_references(refs)
        return nil unless refs.is_a?(Array)

        refs.map do |ref|
          if ref.is_a?(Array) && ref.length == 2
            { type: ref[0], value: ref[1] }
          else
            ref
          end
        end
      end

      # Parse comma-separated reference string
      # Note there can have some issues if the ref values themselves contain commas,
      # but it is the way the MSF RPC API returns them.
      # @param refs [String, nil] Comma-separated refs
      # @return [Array<String>, nil] Array of references
      def self.parse_refs(refs)
        return nil if refs.nil? || refs.empty?
        refs.to_s.split(',').map(&:strip).reject(&:empty?)
      end
    end
  end
end

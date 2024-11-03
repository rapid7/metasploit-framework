# -*- coding: binary -*-

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# https://metasploit.com/framework/
##

module Msf
  class Auxiliary
    ###
    #
    # This module provides a means to report module summaries
    #
    ###
    module ReportSummary
      def initialize(info = {})
        super(info)

        if framework.features.enabled?(Msf::FeatureManager::SHOW_SUCCESSFUL_LOGINS)
          register_options(
            [
              OptBool.new('ShowSuccessfulLogins', [false, 'Outputs a table of successful logins', true]),
            ]
          )
        end
      end

      def run
        return super unless framework.features.enabled?(Msf::FeatureManager::SHOW_SUCCESSFUL_LOGINS) && datastore['ShowSuccessfulLogins']

        @report = {}
        @report.extend(::Rex::Ref)
        rhost_walker = Msf::RhostsWalker.new(datastore['RHOSTS'], datastore).to_enum
        conditional_verbose_output(rhost_walker.count)
        result = super
        print_report_summary
        result
      end

      # Creates a credential and adds to to the DB if one is present
      #
      # @param [Hash] credential_data
      # @return [Metasploit::Credential::Login]
      def create_credential_login(credential_data)
        return super unless framework.features.enabled?(Msf::FeatureManager::SHOW_SUCCESSFUL_LOGINS) && datastore['ShowSuccessfulLogins'] && @report

        credential = {
          public: credential_data[:username],
          private_data: credential_data[:private_data]
        }
        @report[rhost] = { successful_logins: [] }
        @report[rhost][:successful_logins] << credential
        super
      end

      # Creates a credential and adds to to the DB if one is present, then calls create_credential_login to
      # attempt a login
      #
      # This is needed when create_credential_and_login in
      # lib/metasploit/framework/data_service/proxy/credential_data_proxy.rb
      # is called, which doesn't call of to create_credential_login at any point to initialize @report[rhost]
      #
      # This allow modules that make use of create_credential_and_login to make use of the report summary mixin
      #
      # @param [Hash] credential_data
      # @return [Metasploit::Credential::Login]
      def create_credential_and_login(credential_data)
        return super unless framework.features.enabled?(Msf::FeatureManager::SHOW_SUCCESSFUL_LOGINS) && datastore['ShowSuccessfulLogins'] && @report

        credential = {
          public: credential_data[:username],
          private_data: credential_data[:private_data]
        }
        @report[rhost] = { successful_logins: [] }
        @report[rhost][:successful_logins] << credential
        super
      end

      # Framework is notified that we have a new session opened
      #
      # @param [MetasploitModule] obj
      # @param [Object] info
      # @param [Hash] ds_merge
      # @param [FalseClass] crlf
      # @param [Socket] sock
      # @param [Msf::Sessions::<SESSION_CLASS>] sess
      # @return [Msf::Sessions::<SESSION_CLASS>]
      def start_session(obj, info, ds_merge, crlf = false, sock = nil, sess = nil)
        return super unless framework.features.enabled?(Msf::FeatureManager::SHOW_SUCCESSFUL_LOGINS) && datastore['ShowSuccessfulLogins']

        unless @report && @report[rhost]
          elog("No RHOST found in report, skipping reporting for #{rhost}")
          print_brute level: :error, ip: rhost, msg: "No RHOST found in report, skipping reporting for #{rhost}"
          return super
        end

        result = super
        @report[rhost].merge!({ successful_sessions: [] })
        @report[rhost][:successful_sessions] << result
        result
      end

      private

      # Prints a summary of successful logins
      # Returns a ::Rex::Text::Table with the following data: host, public and private credentials for each
      # successful login per host
      #
      # @return [Hash] Rhost keys mapped to successful logins and sessions for each host
      def print_report_summary
        report = @report

        logins = report.flat_map { |_k, v| v[:successful_logins] }.compact
        sessions = report.flat_map { |_k, v| v[:successful_sessions] }.compact

        print_status("Scan completed, #{logins.size} #{logins.size == 1 ? 'credential was' : 'credentials were'} successful.")
        print_successful_logins(report)

        if datastore['CreateSession']
          print_status("#{sessions.size} #{sessions.size == 1 ? 'session was' : 'sessions were'} opened successfully.")
        end

        report
      end

      # Logic to detect if the ShowSuccessLogins datastore option has been set
      #
      # @param [Hash] report Host mapped to successful logins and sessions
      # @return [String] Rex::Text::Table containing successful logins
      def print_successful_logins(report)
        if datastore['ShowSuccessfulLogins'] == true && !report.empty?
          table = successful_logins_to_table(report)
          print_line("\n" + table.to_s + "\n")
        end
      end

      # The idea here is to add a hybrid approach for scanner modules
      # If only one host is scanned a more verbose output is useful to the user
      # If scanning multiple hosts we would want more lightweight information
      #
      # @param [Object] host_count The number of hosts
      def conditional_verbose_output(host_count)
        if host_count == 1
          datastore['Verbose'] = true
        end
      end

      # Takes the login/session results and converts them into a Rex::Text::Table format
      #
      # @param report [Hash{String => [Metasploit::Framework::LoginScanner::Result, Msf::Sessions]}]
      # @return [Rex::Text::WrappedTable] Rex::Text::Table containing successful logins
      def successful_logins_to_table(report)
        field_headers = %w[Host Public Private]

        markdown_fields = report.flat_map do |host, result|
          if result[:successful_logins].nil?
            next
          end

          result[:successful_logins].map do |credential|
            [host, credential[:public], credential[:private_data]]
          end
        end

        ::Rex::Text::Table.new(
          'Header' => 'Successful logins',
          'Indent' => 4,
          'Columns' => field_headers,
          'Rows' => markdown_fields.compact
        )
      end
    end
  end
end

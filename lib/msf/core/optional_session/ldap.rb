# frozen_string_literal: true

module Msf
  module OptionalSession
    module LDAP
      include Msf::OptionalSession

      RHOST_GROUP_OPTIONS = %w[RHOSTS RPORT DOMAIN USERNAME PASSWORD THREADS]
      REQUIRED_OPTIONS = %w[RHOSTS RPORT USERNAME PASSWORD THREADS]

      def initialize(info = {})
        super(
          update_info(
            info,
            'SessionTypes' => %w[ldap]
          )
        )

        if optional_session_enabled?
          register_option_group(name: 'SESSION',
                                description: 'Used when connecting via an existing SESSION',
                                option_names: ['SESSION'])
          register_option_group(name: 'RHOST',
                                description: 'Used when making a new connection via RHOSTS',
                                option_names: RHOST_GROUP_OPTIONS,
                                required_options: REQUIRED_OPTIONS)

          register_options(
            [
              Msf::OptInt.new('SESSION', [ false, 'The session to run this module on' ]),
              Msf::Opt::RHOST(nil, false),
              Msf::Opt::RPORT(389, false)
            ]
          )

          add_info('New in Metasploit 6.4 - This module can target a %grnSESSION%clr or an %grnRHOST%clr')
        end
      end

      def optional_session_enabled?
        framework.features.enabled?(Msf::FeatureManager::LDAP_SESSION_TYPE)
      end

      # @see #ldap_open
      # @return [Object] The result of whatever the block that was
      #   passed in via the "block" parameter yielded.
      def ldap_connect(opts = {}, &block)
        if session && !opts[:base].blank?
          session.client.base = opts[:base]
        end
        return yield session.client if session
        ldap_open(get_connect_opts.merge(opts), &block)
      end

      # Create a new LDAP connection using Rex::Proto::LDAP::Client.new and yield the
      # resulting connection object to the caller of this method.
      #
      # @param opts [Hash] A hash containing the connection options for the
      #   LDAP connection to the target server.
      # @yieldparam ldap [Rex::Proto::LDAP::Client] The LDAP connection handle to use for connecting to
      #   the target LDAP server.
      def ldap_new(opts = {})
        if session && !opts[:base].blank?
          session.client.base = opts[:base]
        end
        return yield session.client if session
        super
      end
    end
  end
end

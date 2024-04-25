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
        else
          register_options(
            [
              Msf::Opt::RHOST,
              Msf::Opt::RPORT(389),
            ]
          )
        end
      end

      def optional_session_enabled?
        framework.features.enabled?(Msf::FeatureManager::LDAP_SESSION_TYPE)
      end
    end
  end
end

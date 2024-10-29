# frozen_string_literal: true

module Msf
  module OptionalSession
    module MSSQL
      include Msf::OptionalSession

      RHOST_GROUP_OPTIONS = %w[RHOSTS RPORT DATABASE USERNAME PASSWORD THREADS]

      def initialize(info = {})
        super(
          update_info(
            info,
            'SessionTypes' => %w[mssql]
          )
        )

        if optional_session_enabled?
          register_option_group(name: 'SESSION',
                                description: 'Used when connecting via an existing SESSION',
                                option_names: ['SESSION'])
          register_option_group(name: 'RHOST',
                                description: 'Used when making a new connection via RHOSTS',
                                option_names: RHOST_GROUP_OPTIONS,
                                required_options: RHOST_GROUP_OPTIONS)
          register_options(
            [
              Msf::OptInt.new('SESSION', [ false, 'The session to run this module on' ]),
              Msf::OptString.new('DATABASE', [ false, 'The database to authenticate against', 'MSSQL']),
              Msf::OptString.new('USERNAME', [ false, 'The username to authenticate as', 'MSSQL']),
              Msf::Opt::RHOST(nil, false),
              Msf::Opt::RPORT(1433, false)
            ]
          )

          add_info('New in Metasploit 6.4 - This module can target a %grnSESSION%clr or an %grnRHOST%clr')
        end
      end

      def optional_session_enabled?
        framework.features.enabled?(Msf::FeatureManager::MSSQL_SESSION_TYPE)
      end
    end
  end
end

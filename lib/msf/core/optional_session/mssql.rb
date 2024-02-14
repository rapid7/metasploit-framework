# frozen_string_literal: true

module Msf
  module OptionalSession
    module MSSQL
      include Msf::OptionalSession

      def initialize(info = {})
        super(
          update_info(
            info,
            'SessionTypes' => %w[MSSQL]
          )
        )

        if framework.features.enabled?(Msf::FeatureManager::MSSQL_SESSION_TYPE)
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

      def session
        return nil unless framework.features.enabled?(Msf::FeatureManager::MSSQL_SESSION_TYPE)

        super
      end
    end
  end
end

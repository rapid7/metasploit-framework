# frozen_string_literal: true

module Msf
  module OptionalSession
    module SMB
      include Msf::OptionalSession

      RHOST_GROUP_OPTIONS = %w[RHOSTS RPORT SMBDomain SMBUser SMBPass THREADS]

      def initialize(info = {})
        super(
          update_info(
            info,
            'SessionTypes' => %w[smb]
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
              Msf::Opt::RHOST(nil, false),
              Msf::Opt::RPORT(445, false)
            ]
          )

          add_info('New in Metasploit 6.4 - This module can target a %grnSESSION%clr or an %grnRHOST%clr')
        end
      end

      def optional_session_enabled?
        framework.features.enabled?(Msf::FeatureManager::SMB_SESSION_TYPE)
      end
    end
  end
end

# -*- coding: binary -*-
#
# frozen_string_literal: true

# A mixin used for providing Modules with post-exploitation options and helper methods
#
module Msf::OptionalSession
  include Msf::SessionCompatibility

  def initialize(info = {})
    super
    if framework.features.enabled?(Msf::FeatureManager::SMB_SESSION_TYPE)
      register_options(
        [
          Msf::OptInt.new('SESSION', [ false, 'The session to run this module on' ]),
          Msf::Opt::RHOST(nil, false),
          Msf::Opt::RPORT(nil, false)
        ]
      )
    end

    if framework.features.enabled?(Msf::FeatureManager::POSTGRESQL_SESSION_TYPE)
      register_options(
        [
          Msf::OptInt.new('SESSION', [ false, 'The session to run this module on' ]),
          Msf::OptString.new('DATABASE', [ false, 'The database to authenticate against', 'postgres']),
          Msf::OptString.new('USERNAME', [ false, 'The username to authenticate as', 'postgres']),
          Msf::Opt::RHOST(nil, false),
          Msf::Opt::RPORT(nil, false)
        ]
      )
    end
  end

  def session
    return nil unless (framework.features.enabled?(Msf::FeatureManager::SMB_SESSION_TYPE) || framework.features.enabled?(Msf::FeatureManager::POSTGRESQL_SESSION_TYPE))

    super
  end
end

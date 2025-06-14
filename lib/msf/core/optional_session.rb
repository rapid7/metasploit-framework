# -*- coding: binary -*-
#
# frozen_string_literal: true

# A mixin used for providing Modules with post-exploitation options and helper methods
#
module Msf
  module OptionalSession
    include Msf::SessionCompatibility

    attr_accessor :session_or_rhost_required

    def session_or_rhost_required?
      @session_or_rhost_required.nil? ? true : @session_or_rhost_required
    end

    # Validates options depending on whether we are using  SESSION or an RHOST for our connection
    def validate
      super
      return unless optional_session_enabled?

      # If the session is set use that by default regardless of rhost being (un)set
      if session
        validate_session
      elsif rhost
        validate_rhost
      elsif session_or_rhost_required?
        raise Msf::OptionValidateError.new(message: 'A SESSION or RHOST must be provided')
      end
    end

    def session
      return nil unless optional_session_enabled?

      super
    end

    protected

    # Used to validate options when RHOST has been set
    def validate_rhost
      validate_group('RHOST')
    end

    # Used to validate options when SESSION has been set
    def validate_session
      issues = {}
      if session_types && !session_types.include?(session.type)
        issues['SESSION'] = "Incompatible session type: #{session.type}. This module works with: #{session_types.join(', ')}."
      end
      raise Msf::OptionValidateError.new(issues.keys.to_a, reasons: issues) unless issues.empty?

      validate_group('SESSION')
    end

    # Validates the options within an option group
    #
    # @param group_name [String] Name of the option group
    def validate_group(group_name)
      option_group = options.groups[group_name]
      option_group.validate(options, datastore) if option_group
    end
  end
end

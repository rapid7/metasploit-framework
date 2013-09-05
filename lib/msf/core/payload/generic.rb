# -*- coding: binary -*-
require 'msf/core'

module Msf

###
#
# The generic payloads are used to define a generalized payload type that
# is both architecture and platform independent.  Under the hood, generic
# payloads seek out the correct payload for the appropriate architecture
# and platform that is being targeted.
#
###
module Payload::Generic

  #
  # Registers options that are common to all generic payloads, such as
  # platform and arch.
  #
  def initialize(info = {})
    super(merge_info(info,
      'Arch'     => ARCH_ALL - [ARCH_TTY],
      'Platform' => ''))

    register_advanced_options(
      [
        OptString.new('PLATFORM',
          [
            false,
            "The platform that is being targeted",
            nil
          ]),
        OptString.new('ARCH',
          [
            false,
            "The architecture that is being targeted",
            nil
          ])
      ], Msf::Payload::Generic)
  end

  #
  # Reset's the generic payload's internal state so that it can find a new
  # actual payload.
  #
  def reset
    self.explicit_arch     = nil
    self.explicit_platform = nil
    self.actual_payload    = nil
  end

  #
  # Generate is different from other methods -- it will try to re-detect
  # the actual payload in case settings have changed.  Other methods will
  # use the cached version if possible.
  #
  def generate
    reset

    redirect_to_actual(:generate)
  end

  #
  # Overrides -- we have to redirect all potential payload methods
  # to the actual payload so that they get handled appropriately, cuz
  # we're like a proxy and stuff.  We can't use method_undefined
  # because all of these methods are actually defined.
  #

  def payload
    redirect_to_actual(:payload)
  end

  def offsets
    redirect_to_actual(:offsets)
  end

  def substitute_vars(*args)
    redirect_to_actual(:substitute_vars, *args)
  end

  def replace_var(*args)
    redirect_to_actual(:replace_var, *args)
  end

  def compatible_encoders
    redirect_to_actual(:compatible_encoders)
  end

  def compatible_nops
    redirect_to_actual(:compatible_nops)
  end

  def handle_connection(*args)
    redirect_to_actual(:handle_connection, *args)
  end

  def on_session(*args)
    redirect_to_actual(:on_session, *args)
  end

  #
  # Stager overrides
  #

  def stage_payload
    redirect_to_actual(:stage_payload)
  end

  def stage_offsets
    redirect_to_actual(:stage_offsets)
  end

  def stager_payload
    redirect_to_actual(:stager_payload)
  end

  def stager_offsets
    redirect_to_actual(:stager_offsets)
  end

  def stage_over_connection?
    redirect_to_actual(:stage_over_connection?)
  end

  def generate_stage
    redirect_to_actual(:generate_stage)
  end

  def handle_connection_stage(*args)
    redirect_to_actual(:handle_connection_stage, *args)
  end

  def handle_intermediate_stage(*args)
    redirect_to_actual(:handle_intermediate_stage, *args)
  end

  def stage_prefix
    redirect_to_actual(:stage_prefix)
  end

  def stage_prefix=(*args)
    redirect_to_actual(:stage_prefix=, *args)
  end

  def user_input=(h)
    @user_input = h
    redirect_to_actual(:user_input, h) if actual_payload
  end

  def user_output=(h)
    @user_output = h
    redirect_to_actual(:user_output, h) if actual_payload
  end

  #
  # First, find the underlying payload and then pass all methods onto it.
  #
  def redirect_to_actual(name, *args)
    find_actual_payload
    actual_payload.send(name, *args)
  end

  #
  # Accessor that makes it possible to define an explicit platform.  This is
  # used for things like payload regeneration.
  #
  attr_accessor :explicit_platform
  #
  # Accessor that makes it possible to define an explicit architecture.  This
  # is used for things like payload regeneration.
  #
  attr_accessor :explicit_arch

protected

  #
  # The actual underlying platform/arch-specific payload instance that should
  # be used.
  #
  attr_accessor :actual_payload

  #
  # Returns the actual platform that should be used for the payload.
  #
  def actual_platform
    platform = nil

    if explicit_platform.nil? == false
      platform = explicit_platform
    elsif datastore['PLATFORM']
      platform = datastore['PLATFORM']
    elsif assoc_exploit
      platform = assoc_exploit.target_platform
    end

    # If we still have an invalid platform, then we suck.
    if platform.nil?
      raise NoCompatiblePayloadError, "A platform could not be determined by the generic payload"
    elsif platform.kind_of?(String)
      platform = Msf::Module::PlatformList.transform(platform)
    end

    return platform
  end

  #
  # Returns the actual architecture that should be used for the payload.
  #
  def actual_arch
    arch = nil

    if explicit_arch.nil? == false
      arch = explicit_arch
    elsif datastore['ARCH']
      arch = datastore['ARCH']
    elsif assoc_exploit
      arch = assoc_exploit.target_arch || ARCH_X86
    end

    # If we still have an invalid architecture, then we suck.
    if arch.nil?
      raise NoCompatiblePayloadError, "An architecture could not be determined by the generic payload"
    elsif arch.kind_of?(String)
      arch = [ arch ]
    end

    return arch
  end

  def find_actual_payload
    return if not actual_payload.nil?

    # Look for one based on the exploit's compatible set
    if(assoc_exploit)
      self.actual_payload = framework.payloads.find_payload_from_set(
        assoc_exploit.compatible_payloads,
        actual_platform,
        actual_arch,
        handler_klass,
        session,
        payload_type)
    end

    # Fall back to the generic match (ignores size, compat flags, etc)
    if(actual_payload.nil?)
      self.actual_payload = framework.payloads.find_payload(
        actual_platform,
        actual_arch,
        handler_klass,
        session,
        payload_type)
    end

    if actual_payload.nil?
      raise NoCompatiblePayloadError, "Could not locate a compatible payload for #{actual_platform.names.join("/")}/#{actual_arch}"
    else
      dlog("Selected payload #{actual_payload.refname} from generic payload #{refname}", 'core', LEV_2)
      # Share our datastore with the actual payload so that it has the
      # appropriate values to substitute ad so on.
      self.actual_payload.share_datastore(self.datastore)

      # Set the associated exploit for the payload.
      self.actual_payload.assoc_exploit  = self.assoc_exploit

      # Set the parent payload to this payload so that we can handle
      # things like session creation (so that event notifications will
      # work properly)
      self.actual_payload.parent_payload = self

      # Set the cached user_input/user_output
      self.actual_payload.user_input  = self.user_input
      self.actual_payload.user_output = self.user_output
    end


  end


end

end


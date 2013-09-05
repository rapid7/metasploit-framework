# -*- coding: binary -*-
require 'msf/core'
require 'msf/core/option_container'

###
#
# Base mixin interface for use by stagers.
#
###
module Msf::Payload::Stager

  def initialize(info={})
    super

    register_advanced_options(
      [
        Msf::OptBool.new("EnableStageEncoding", [ false, "Encode the second stage payload", false ]),
        Msf::OptString.new("StageEncoder", [ false, "Encoder to use if EnableStageEncoding is set", nil ]),
      ], Msf::Payload::Stager)

  end

  #
  # Sets the payload type to a stager.
  #
  def payload_type
    return Msf::Payload::Type::Stager
  end

  #
  # Return the stager payload's raw payload.
  #
  # Can be nil if the stager is not pre-assembled.
  #
  # @return [String,nil]
  def payload
    return module_info['Stager']['Payload']
  end

  #
  # Return the stager payload's assembly text, if any.
  #
  # @return [String,nil]
  def assembly
    return module_info['Stager']['Assembly']
  end

  #
  # Return the stager payload's offsets.
  #
  # These will be used for substitutions during stager generation.
  #
  # @return [Hash]
  def offsets
    return module_info['Stager']['Offsets']
  end

  #
  # Returns the raw stage payload.
  #
  # Can be nil if the final stage is not pre-assembled.
  #
  # @return [String,nil]
  def stage_payload
    return module_info['Stage']['Payload']
  end

  #
  # Returns the assembly text of the stage payload.
  #
  # @return [String]
  def stage_assembly
    return module_info['Stage']['Assembly']
  end

  #
  # Returns variable offsets within the stage payload.
  #
  # These will be used for substitutions during generation of the final
  # stage.
  #
  # @return [Hash]
  def stage_offsets
    return module_info['Stage']['Offsets']
  end

  #
  # Whether or not any stages associated with this stager should be sent over
  # the connection that is established.
  #
  def stage_over_connection?
    true
  end


  #
  # Whether to use an Encoder on the second stage
  #
  # @return [Boolean]
  def encode_stage?
    # Convert to string in case it hasn't been normalized
    !!(datastore['EnableStageEncoding'].to_s == "true")
  end

  #
  # Generates the stage payload and substitutes all offsets.
  #
  # @return [String] The generated payload stage, as a string.
  def generate_stage
    # XXX: This is nearly identical to Payload#internal_generate

    # Compile the stage as necessary
    if stage_assembly and !stage_assembly.empty?
      raw = build(stage_assembly, stage_offsets)
    else
      raw = stage_payload.dup
    end

    # Substitute variables in the stage
    substitute_vars(raw, stage_offsets) if (stage_offsets)

    return raw
  end

  #
  # Transmit the associated stage.
  #
  # @param (see handle_connection_stage)
  # @return (see handle_connection_stage)
  def handle_connection(conn, opts={})
    # If the stage should be sent over the client connection that is
    # established (which is the default), then go ahead and transmit it.
    if (stage_over_connection?)
      p = generate_stage

      # Encode the stage if stage encoding is enabled
      p = encode_stage(p)

      # Give derived classes an opportunity to an intermediate state before
      # the stage is sent.  This gives derived classes an opportunity to
      # augment the stage and the process through which it is read on the
      # remote machine.
      #
      # If we don't use an intermediate stage, then we need to prepend the
      # stage prefix, such as a tag
      if handle_intermediate_stage(conn, p) == false
        p = (self.stage_prefix || '') + p
      end

      sending_msg = "Sending #{encode_stage? ? "encoded ":""}stage"
      sending_msg << " (#{p.length} bytes)"
      # The connection should always have a peerhost (even if it's a
      # tunnel), but if it doesn't, erroring out here means losing the
      # session, so make sure it does, just to be safe.
      if conn.respond_to? :peerhost
        sending_msg << " to #{conn.peerhost}"
      end
      print_status(sending_msg)

      # Send the stage
      conn.put(p)
    end

    # If the stage implements the handle connection method, sleep before
    # handling it.
    if (derived_implementor?(Msf::Payload::Stager, 'handle_connection_stage'))
      print_status("Sleeping before handling stage...")

      # Sleep before processing the stage
      Rex::ThreadSafe.sleep(1.5)
    end

    # Give the stages a chance to handle the connection
    handle_connection_stage(conn, opts)
  end

  #
  # Allow the stage to process whatever it is it needs to process.
  #
  # Override to deal with sending the final stage in cases where
  # {#generate_stage} is not the whole picture, such as when uploading
  # an executable. The default is to simply attempt to create a session
  # on the given +conn+ socket with {Msf::Handler#create_session}.
  #
  # @param (see Handler#create_session)
  # @return (see Handler#create_session)
  def handle_connection_stage(conn, opts={})
    create_session(conn, opts)
  end

  #
  # Gives derived classes an opportunity to alter the stage and/or
  # encapsulate its transmission.
  #
  def handle_intermediate_stage(conn, payload)
    false
  end

  # Encodes the stage prior to transmission
  # @return [String] Encoded version of +stg+
  def encode_stage(stg)
    return stg unless encode_stage?

    if datastore["StageEncoder"].nil? or datastore["StageEncoder"].empty?
      stage_enc_mod = nil
    else
      stage_enc_mod = datastore["StageEncoder"]
    end

    # Generate an encoded version of the stage.  We tell the encoding system
    # to save edi to ensure that it does not get clobbered.
    encp = Msf::EncodedPayload.create(
      self,
      'Raw'           => stg,
      'Encoder'       => stage_enc_mod,
      'SaveRegisters' => ['edi'],
      'ForceEncode'   => true)
    print_status("Encoded stage with #{encp.encoder.refname}")

    # If the encoding succeeded, use the encoded buffer.  Otherwise, fall
    # back to using the non-encoded stage
    encp.encoded || stg
  end

  # Aliases
  alias stager_payload payload
  alias stager_offsets offsets

  #
  # A value that should be prefixed to a stage, such as a tag.
  #
  attr_accessor :stage_prefix

end


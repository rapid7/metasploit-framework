# -*- coding: binary -*-
require 'msf/core'
require 'msf/core/option_container'
require 'msf/core/payload/transport_config'

###
#
# Base mixin interface for use by stagers.
#
###
module Msf::Payload::Stager

  include Msf::Payload::TransportConfig

  def initialize(info={})
    super

    register_advanced_options(
      [
        Msf::OptBool.new("EnableStageEncoding", [ false, "Encode the second stage payload", false ]),
        Msf::OptString.new("StageEncoder", [ false, "Encoder to use if EnableStageEncoding is set", nil ]),
        Msf::OptString.new("StageEncoderSaveRegisters", [ false, "Additional registers to preserve in the staged payload if EnableStageEncoding is set", "" ]),
        Msf::OptBool.new("StageEncodingFallback", [ false, "Fallback to no encoding if the selected StageEncoder is not compatible", true ])
      ], Msf::Payload::Stager)

  end

  #
  # Perform attempt at detecting the appropriate transport config.
  # Call the determined config with passed options.
  # Override this in stages/stagers to use specific transports
  #
  def transport_config(opts={})
    if self.refname =~ /reverse_/
        direction = 'reverse'
    else
        direction = 'bind'
    end

    if self.refname =~ /_tcp/
        proto = 'tcp'
    elsif self.refname =~ /_https/
        proto = 'https'
    else
        proto = 'http'
    end
    send("transport_config_#{direction}_#{proto}", opts)
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
  def stage_payload(opts = {})
    if module_info['Stage']
      return module_info['Stage']['Payload']
    end
    nil
  end

  #
  # Returns the assembly text of the stage payload.
  #
  # @return [String]
  def stage_assembly
    if module_info['Stage']
      return module_info['Stage']['Assembly']
    end
    nil
  end

  #
  # Returns variable offsets within the stage payload.
  #
  # These will be used for substitutions during generation of the final
  # stage.
  #
  # @return [Hash]
  def stage_offsets
    if module_info['Stage']
      return module_info['Stage']['Offsets']
    end
    nil
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
    !!(datastore['EnableStageEncoding'])
  end

  #
  # Generates the stage payload and substitutes all offsets.
  #
  # @return [String] The generated payload stage, as a string.
  def generate_stage(opts={})
    # XXX: This is nearly identical to Payload#internal_generate

    # Compile the stage as necessary
    if stage_assembly and !stage_assembly.empty?
      raw = build(stage_assembly, stage_offsets)
    else
      raw = stage_payload(opts)
    end

    # Substitute variables in the stage
    substitute_vars(raw, stage_offsets) if (stage_offsets)

    return raw
  end

  def sends_hex_uuid?
    false
  end

  def format_uuid(uuid)
    if sends_hex_uuid?
      return uuid
    end

    return Msf::Payload::UUID.new({raw: uuid_raw})
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
      if respond_to? :include_send_uuid
        if include_send_uuid
          uuid_raw = conn.get_once(16, 1)
          if uuid_raw
            opts[:uuid] = format_uuid(uuid_raw)
          end
        end
      end

      p = generate_stage(opts)

      # Encode the stage if stage encoding is enabled
      begin
        p = encode_stage(p)
      rescue ::RuntimeError
        warning_msg = "Failed to stage"
        warning_msg << " (#{conn.peerhost})"  if conn.respond_to? :peerhost
        warning_msg << ": #{$!}"
        print_warning warning_msg
        if conn.respond_to? :close && !conn.closed?
          conn.close
        end
        return
      end

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

  #
  # Takes an educated guess at the list of registers an encoded stage
  # would need to preserve based on the Convention
  #
  def encode_stage_preserved_registers
    module_info['Convention'].to_s.scan(/\bsock([a-z]{3,}+)\b/).
      map {|reg| reg.first }.
      join(" ")
  end

  # Encodes the stage prior to transmission
  # @return [String] Encoded version of +stg+
  def encode_stage(stg)
    return stg unless encode_stage?
    stage_enc_mod = nil

    # Handle StageEncoder if specified by the user
    if datastore['StageEncoder'].to_s.length > 0
      stage_enc_mod = datastore["StageEncoder"]
    end

    # Allow the user to specify additional registers to preserve
    saved_registers =
      datastore['StageEncoderSaveRegisters'].to_s +
      " " +
      encode_stage_preserved_registers
    saved_registers.strip!

    estg = nil
    begin
      # Generate an encoded version of the stage.  We tell the encoding system
      # to save certain registers to ensure that it does not get clobbered.
      encp = Msf::EncodedPayload.create(
        self,
        'Raw'                => stg,
        'Encoder'            => stage_enc_mod,
        'EncoderOptions'     => { 'SaveRegisters' => saved_registers },
        'ForceSaveRegisters' => true,
        'ForceEncode'        => true)

      if encp.encoder
        if stage_enc_mod
          print_status("Encoded stage with #{stage_enc_mod}")
        else
          print_status("Encoded stage with #{encp.encoder.refname}")
        end
        estg = encp.encoded
      end
    rescue
      if datastore['StageEncodingFallback'] && estg.nil?
        print_warning("StageEncoder failed, falling back to no encoding")
        estg = stg
      else
        raise RuntimeError, "Stage encoding failed and StageEncodingFallback is disabled"
      end
    end

    estg
  end

  # Aliases
  alias stager_payload payload
  alias stager_offsets offsets

  #
  # A value that should be prefixed to a stage, such as a tag.
  #
  attr_accessor :stage_prefix

end


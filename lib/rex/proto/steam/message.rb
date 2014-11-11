# -*- coding: binary -*-


module Rex
module Proto
##
#
# Steam protocol support, taken from https://developer.valvesoftware.com/wiki/Server_queries
#
##
module Steam

  FRAGMENTED_HEADER = 0xFFFFFFFE
  UNFRAGMENTED_HEADER = 0xFFFFFFFF

  def decode_message(message)
    # minimum size is header (4) + type (1)
    return if message.length < 5
    header, type = message.unpack('NC')
    # TODO: handle fragmented responses
    return if header != UNFRAGMENTED_HEADER
    [header, type, message[5, message.length]]
  end

  def encode_message(type, payload)
    if type.is_a? Fixnum
      type_num = type
    elsif type.is_a? String
      type_num = type.ord
    else
      fail ArgumentError, 'type must be a String or Fixnum'
    end

    [UNFRAGMENTED_HEADER, type_num ].pack('NC') + payload
  end

  def a2s_info
    encode_message('T', "Source Engine Query\x00")
  end

  def a2s_info_decode(message)
    # abort if it is impossibly short
    return nil if message.length < 19
    _header, message_type, payload = decode_message(message)
    # abort if it isn't a valid Steam response
    return nil if message_type != 0x49 # 'I'
    info = {}
    info[:version], info[:name], info[:map], info[:folder], info[:game_name],
      info[:game_id], players, players_max, info[:bots],
      type, env, vis, vac, info[:game_version], edf = payload.unpack("CZ*Z*Z*Z*SCCCCCCCZ*C")

    # translate type
    case type
    when 100 # d
      server_type = 'Dedicated'
    when 108 # l
      server_type = 'Non-dedicated'
    when 112 # p
      server_type = 'SourceTV relay (proxy)'
    else
      server_type = "Unknown (#{type})"
    end
    info[:type] = server_type

    # translate environment
    case env
    when 108 # l
      server_env = 'Linux'
    when 119 # w
      server_env = 'Windows'
    when 109 # m
    when 111 # o
      server_env = 'Mac'
    else
      server_env = "Unknown (#{env})"
    end
    info[:environment] = server_env

    # translate visibility
    case vis
    when 0
      server_vis = 'public'
    when 1
      server_vis = 'private'
    else
      server_vis = "Unknown (#{vis})"
    end
    info[:visibility] = server_vis

    # translate VAC
    case vac
    when 0
      server_vac = 'unsecured'
    when 1
      server_vac = 'secured'
    else
      server_vac = "Unknown (#{vac})"
    end
    info[:VAC] = server_vac

    # format players/max
    info[:players] = "#{players}/#{players_max}"

    # TODO: parse EDF
    info
  end
end
end
end

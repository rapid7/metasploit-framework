module Metasploit
module Framework
module MSSQL

# A base mixin of useful mssql methods for parsing structures etc
module Base

  # Encryption
  ENCRYPT_OFF     = 0x00 #Encryption is available but off.
  ENCRYPT_ON      = 0x01 #Encryption is available and on.
  ENCRYPT_NOT_SUP = 0x02 #Encryption is not available.
  ENCRYPT_REQ     = 0x03 #Encryption is required.

  # Packet Type
  TYPE_SQL_BATCH                   = 1  # (Client) SQL command
  TYPE_PRE_TDS7_LOGIN              = 2  # (Client) Pre-login with version < 7 (unused)
  TYPE_RPC                         = 3  # (Client) RPC
  TYPE_TABLE_RESPONSE              = 4  # (Server)  Pre-Login Response ,Login Response, Row Data, Return Status, Return Parameters,
  # Request Completion, Error and Info Messages, Attention Acknowledgement
  TYPE_ATTENTION_SIGNAL            = 6  # (Client) Attention
  TYPE_BULK_LOAD                   = 7  # (Client) SQL Command with binary data
  TYPE_TRANSACTION_MANAGER_REQUEST = 14 # (Client) Transaction request manager
  TYPE_TDS7_LOGIN                  = 16 # (Client) Login
  TYPE_SSPI_MESSAGE                = 17 # (Client) Login
  TYPE_PRE_LOGIN_MESSAGE           = 18 # (Client) pre-login with version > 7

  # Status
  STATUS_NORMAL                  = 0x00
  STATUS_END_OF_MESSAGE          = 0x01
  STATUS_IGNORE_EVENT            = 0x02
  STATUS_RESETCONNECTION         = 0x08 # TDS 7.1+
  STATUS_RESETCONNECTIONSKIPTRAN = 0x10 # TDS 7.3+

  #
  # Send and receive using TDS
  #
  def mssql_send_recv(req, timeout=15, check_status = true)
    sock.put(req)

    # Read the 8 byte header to get the length and status
    # Read the length to get the data
    # If the status is 0, read another header and more data

    done = false
    resp = ""

    while(not done)
      head = sock.get_once(8, timeout)
      if !(head && head.length == 8)
        return false
      end

      # Is this the last buffer?
      if head[1, 1] == "\x01" || !check_status
        done = true
      end

      # Grab this block's length
      rlen = head[2, 2].unpack('n')[0] - 8

      while(rlen > 0)
        buff = sock.get_once(rlen, timeout)
        return if not buff
        resp << buff
        rlen -= buff.length
      end
    end

    resp
  end

  #
  # Encrypt a password according to the TDS protocol (encode)
  #
  def mssql_tds_encrypt(pass)
    # Convert to unicode, swap 4 bits both ways, xor with 0xa5
    Rex::Text.to_unicode(pass).unpack('C*').map {|c| (((c & 0x0f) << 4) + ((c & 0xf0) >> 4)) ^ 0xa5 }.pack("C*")
  end

  #
  # Parse a raw TDS reply from the server
  #
  def mssql_parse_tds_reply(data, info)
    info[:errors] ||= []
    info[:colinfos] ||= []
    info[:colnames] ||= []

    # Parse out the columns
    cols = data.slice!(0, 2).unpack('v')[0]
    0.upto(cols-1) do |col_idx|
      col = {}
      info[:colinfos][col_idx] = col

      col[:utype] = data.slice!(0, 2).unpack('v')[0]
      col[:flags] = data.slice!(0, 2).unpack('v')[0]
      col[:type]  = data.slice!(0, 1).unpack('C')[0]

      case col[:type]
      when 48
        col[:id] = :tinyint

      when 52
        col[:id] = :smallint

      when 56
        col[:id] = :rawint

      when 61
        col[:id] = :datetime

      when 34
        col[:id]            = :image
        col[:max_size]      = data.slice!(0, 4).unpack('V')[0]
        col[:value_length]  = data.slice!(0, 2).unpack('v')[0]
        col[:value]         = data.slice!(0, col[:value_length]  * 2).gsub("\x00", '')

      when 36
        col[:id] = :string

      when 38
        col[:id] = :int
        col[:int_size] = data.slice!(0, 1).unpack('C')[0]

      when 127
        col[:id] = :bigint

      when 165
        col[:id] = :hex
        col[:max_size] = data.slice!(0, 2).unpack('v')[0]

      when 173
        col[:id] = :hex # binary(2)
        col[:max_size] = data.slice!(0, 2).unpack('v')[0]

      when 231, 175, 167, 239
        col[:id] = :string
        col[:max_size] = data.slice!(0, 2).unpack('v')[0]
        col[:codepage] = data.slice!(0, 2).unpack('v')[0]
        col[:cflags] = data.slice!(0, 2).unpack('v')[0]
        col[:charset_id] =  data.slice!(0, 1).unpack('C')[0]

      else
        col[:id] = :unknown
      end

      col[:msg_len] = data.slice!(0, 1).unpack('C')[0]

      if col[:msg_len] && col[:msg_len] > 0
        col[:name] = data.slice!(0, col[:msg_len] * 2).gsub("\x00", '')
      end
      info[:colnames] << (col[:name] || 'NULL')
    end
  end

  #
  # Parse individual tokens from a TDS reply
  #
  def mssql_parse_reply(data, info)
    info[:errors] = []
    return if not data
    until data.empty?
      token = data.slice!(0, 1).unpack('C')[0]
      case token
      when 0x81
        mssql_parse_tds_reply(data, info)
      when 0xd1
        mssql_parse_tds_row(data, info)
      when 0xe3
        mssql_parse_env(data, info)
      when 0x79
        mssql_parse_ret(data, info)
      when 0xfd, 0xfe, 0xff
        mssql_parse_done(data, info)
      when 0xad
        mssql_parse_login_ack(data, info)
      when 0xab
        mssql_parse_info(data, info)
      when 0xaa
        mssql_parse_error(data, info)
      when nil
        break
      else
        info[:errors] << "unsupported token: #{token}"
      end
    end
    info
  end

  #
  # Parse a single row of a TDS reply
  #
  def mssql_parse_tds_row(data, info)
    info[:rows] ||= []
    row = []

    info[:colinfos].each do |col|

      if(data.length == 0)
        row << "<EMPTY>"
        next
      end

      case col[:id]
      when :hex
        str = ""
        len = data.slice!(0, 2).unpack('v')[0]
        if len > 0 && len < 65535
          str << data.slice!(0, len)
        end
        row << str.unpack("H*")[0]

      when :string
        str = ""
        len = data.slice!(0, 2).unpack('v')[0]
        if len > 0 && len < 65535
          str << data.slice!(0, len)
        end
        row << str.gsub("\x00", '')

      when :datetime
        row << data.slice!(0, 8).unpack("H*")[0]

      when :rawint
        row << data.slice!(0, 4).unpack('V')[0]

      when :bigint
        row << data.slice!(0, 8).unpack("H*")[0]

      when :smallint
        row << data.slice!(0, 2).unpack("v")[0]

      when :smallint3
        row << [data.slice!(0, 3)].pack("Z4").unpack("V")[0]

      when :tinyint
        row << data.slice!(0, 1).unpack("C")[0]

      when :image
        str = ''
        len = data.slice!(0, 1).unpack('C')[0]
        str = data.slice!(0, len) if len && len > 0
        row << str.unpack("H*")[0]

      when :int
        len = data.slice!(0, 1).unpack("C")[0]
        raw = data.slice!(0, len) if len && len > 0

        case len
        when 0, 255
          row << ''
        when 1
          row << raw.unpack("C")[0]
        when 2
          row << raw.unpack('v')[0]
        when 4
          row << raw.unpack('V')[0]
        when 5
          row << raw.unpack('V')[0] # XXX: missing high byte
        when 8
          row << raw.unpack('VV')[0] # XXX: missing high dword
        else
          info[:errors] << "invalid integer size: #{len} #{data[0, 16].unpack("H*")[0]}"
        end
      else
        info[:errors] << "unknown column type: #{col.inspect}"
      end
    end

    info[:rows] << row
    info
  end

  #
  # Parse a "ret" TDS token
  #
  def mssql_parse_ret(data, info)
    ret = data.slice!(0, 4).unpack('N')[0]
    info[:ret] = ret
    info
  end

  #
  # Parse a "done" TDS token
  #
  def mssql_parse_done(data, info)
    status, cmd, rows = data.slice!(0, 8).unpack('vvV')
    info[:done] = { :status => status, :cmd => cmd, :rows => rows }
    info
  end

  #
  # Parse an "error" TDS token
  #
  def mssql_parse_error(data, info)
    len  = data.slice!(0, 2).unpack('v')[0]
    buff = data.slice!(0, len)

    errno, state, sev, elen = buff.slice!(0, 8).unpack('VCCv')
    emsg = buff.slice!(0, elen * 2)
    emsg.gsub!("\x00", '')

    info[:errors] << "SQL Server Error ##{errno} (State:#{state} Severity:#{sev}): #{emsg}"
    info
  end

  #
  # Parse an "environment change" TDS token
  #
  def mssql_parse_env(data, info)
    len  = data.slice!(0, 2).unpack('v')[0]
    buff = data.slice!(0, len)
    type = buff.slice!(0, 1).unpack('C')[0]

    nval = ''
    nlen = buff.slice!(0, 1).unpack('C')[0] || 0
    nval = buff.slice!(0, nlen * 2).gsub("\x00", '') if nlen > 0

    oval = ''
    olen = buff.slice!(0, 1).unpack('C')[0] || 0
    oval = buff.slice!(0, olen * 2).gsub("\x00", '') if olen > 0

    info[:envs] ||= []
    info[:envs] << { :type => type, :old => oval, :new => nval }
    info
  end

  #
  # Parse an "information" TDS token
  #
  def mssql_parse_info(data, info)
    len  = data.slice!(0, 2).unpack('v')[0]
    buff = data.slice!(0, len)

    errno, state, sev, elen = buff.slice!(0, 8).unpack('VCCv')
    emsg = buff.slice!(0, elen * 2)
    emsg.gsub!("\x00", '')

    info[:infos] ||= []
    info[:infos] << "SQL Server Info ##{errno} (State:#{state} Severity:#{sev}): #{emsg}"
    info
  end

  #
  # Parse a "login ack" TDS token
  #
  def mssql_parse_login_ack(data, info)
    len = data.slice!(0, 2).unpack('v')[0]
    _buff = data.slice!(0, len)
    info[:login_ack] = true
  end
end
end
end
end

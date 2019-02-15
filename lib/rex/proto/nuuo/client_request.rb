# -*- coding: binary -*-

module Rex
module Proto
module Nuuo

class ClientRequest

  DefaultConfig = {
    #
    # Nuuo stuff
    #
    'method'          =>  'USERLOGIN',
    'server_version'     =>  nil,
    #'username'        =>  nil,
    #'password'        =>  nil,
    #'timezone'        =>  nil,
    'data'            =>  nil,
    'headers'         =>  nil,
    'proto'           => 'NUCM',
    'version'         => '1.0',
    'file_name'       =>  nil,
    'file_type'       =>  nil,
    'user_session'    =>  nil,
    #'device_id'       =>  nil,
    #'source_server'   =>  nil,
    #'last_one'        =>  nil,
  }

  attr_reader :opts

  def initialize(opts={})
    @opts = DefaultConfig.merge(opts)
    @opts['headers'] ||= {}
  end

  def to_s
    # Set default header: <method> <proto/version>
    req = ''
    req << set_method
    req << ' '
    req << set_proto_version

    # Set headers
    req << set_header('server_version', 'Version')
    #req << set_header('username', 'Username')
    #req << set_length_header('password', 'Password-Length')
    #req << set_length_header('timezone', 'TimeZone-Length')
    req << set_header('file_name', 'FileName')
    req << set_header('file_type', 'FileType')
    #req << set_length_header('data', 'Content-Length')
    req << set_header('user_session', 'User-Session-No')

    # Add any additional headers
    req << set_extra_headers

    # Set data
    req << set_body
  end

  def set_method
    "#{opts['method']}"
  end

  def set_proto_version
    "#{opts['proto']}/#{opts['version']}\r\n"
  end

  #
  # Return <name> header
  #
  def set_header(key, name)
    if opts['headers'] && opts['headers'].keys.map(&:downcase).include?(name.downcase)
      return ''
    end

    opts[key] ? set_formatted_header(name, opts[key]) : ''
  end

  # Return <name> length header
  def set_length_header(key, name)
    if opts['headers'] && opts['headers'].keys.map(&:downcase).include?(name)
      return ''
    end

    return '' unless opts[key]
    set_formatted_header(name, opts[key].to_s.length)
  end

  #
  # Return additional headers
  #
  def set_extra_headers
    buf = ''
    opts['headers'].each_pair do |var,val|
      buf << set_formatted_header(var,val)
    end

    buf
  end

  def set_body
    return "\r\n#{opts['data']}"
  end

  def set_formatted_header(var, val)
    "#{var}: #{val}\r\n"
  end

end
end
end
end

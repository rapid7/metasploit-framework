# -*- coding: binary -*-
require 'uri'

require 'rex/mime'
require 'rex/socket'
require 'rex/text'

require 'pp'

module Rex
module Proto
module Http

class ClientRequest

  DefaultConfig = {
    #
    # Regular HTTP stuff
    #
    'agent'                  => nil,
    'cgi'                    => true,
    'cookie'                 => nil,
    'data'                   => '',
    'headers'                => nil,
    'raw_headers'            => '',
    'method'                 => 'GET',
    'partial'                => false,
    'path_info'              => '',
    'port'                   => 80,
    'proto'                  => 'HTTP',
    'query'                  => '',
    'ssl'                    => false,
    'uri'                    => '/',
    'vars_get'               => {},
    'vars_post'              => {},
    'vars_form_data'         => [],
    'version'                => '1.1',
    'vhost'                  => nil,
    'ssl_server_name_indication' => nil,

    #
    # Evasion options
    #
    'encode_params'          => true,
    'encode'                 => false,
    'uri_encode_mode'        => 'hex-normal', # hex-normal, hex-all, hex-noslashes, hex-random, u-normal, u-all, u-noslashes, u-random
    'uri_encode_count'       => 1,       # integer
    'uri_full_url'           => false,   # bool
    'pad_method_uri_count'   => 1,       # integer
    'pad_uri_version_count'  => 1,       # integer
    'pad_method_uri_type'    => 'space', # space, tab, apache
    'pad_uri_version_type'   => 'space', # space, tab, apache
    'method_random_valid'    => false,   # bool
    'method_random_invalid'  => false,   # bool
    'method_random_case'     => false,   # bool
    'version_random_valid'   => false,   # bool
    'version_random_invalid' => false,   # bool
    'uri_dir_self_reference' => false,   # bool
    'uri_dir_fake_relative'  => false,   # bool
    'uri_use_backslashes'    => false,   # bool
    'pad_fake_headers'       => false,   # bool
    'pad_fake_headers_count' => 16,      # integer
    'pad_get_params'         => false,   # bool
    'pad_get_params_count'   => 8,       # integer
    'pad_post_params'        => false,   # bool
    'pad_post_params_count'  => 8,       # integer
    'uri_fake_end'           => false,   # bool
    'uri_fake_params_start'  => false,   # bool
    'shuffle_get_params'     => false,   # bool
    'shuffle_post_params'    => false,   # bool
    'header_folding'         => false,   # bool
    'chunked_size'           => 0,        # integer

    #
    # NTLM Options
    #
    'usentlm2_session' => true,
    'use_ntlmv2'       => true,
    'send_lm'         => true,
    'send_ntlm'       => true,
    'SendSPN'  => true,
    'UseLMKey' => false,
    'domain' => 'WORKSTATION',
    #
    # Digest Options
    #
    'DigestAuthIIS' => true
  }

  attr_reader :opts

  def initialize(opts={})
    @opts = DefaultConfig.merge(opts)
    @opts['agent'] ||= Rex::UserAgent.session_agent
    @opts['headers'] ||= {}
  end

  def to_s(headers_only: false)
    # Start GET query string
    qstr = opts['query'] ? opts['query'].dup : ""

    # Start POST data string
    pstr = opts['data'] ? opts['data'].dup : ""

    ctype = opts['ctype']

    if opts['cgi']
      uri_str = set_uri

      if (opts['pad_get_params'])
        1.upto(opts['pad_get_params_count'].to_i) do |i|
          qstr << '&' if qstr.length > 0
          qstr << set_encode_uri(Rex::Text.rand_text_alphanumeric(rand(32)+1))
          qstr << '='
          qstr << set_encode_uri(Rex::Text.rand_text_alphanumeric(rand(32)+1))
        end
      end
      if opts.key?("vars_get") && opts['vars_get']
        opts['vars_get'] = Hash[opts['vars_get'].to_a.shuffle] if (opts['shuffle_get_params'])

        opts['vars_get'].each_pair do |var,val|
          var = var.to_s

          qstr << '&' if qstr.length > 0
          qstr << (opts['encode_params'] ? set_encode_uri(var) : var)
          # support get parameter without value
          # Example: uri?parameter
          if val
            val = val.to_s
            qstr << '='
            qstr << (opts['encode_params'] ? set_encode_uri(val) : val)
          end
        end
      end
      if (opts['pad_post_params'])
        1.upto(opts['pad_post_params_count'].to_i) do |i|
          rand_var = Rex::Text.rand_text_alphanumeric(rand(32)+1)
          rand_val = Rex::Text.rand_text_alphanumeric(rand(32)+1)
          pstr << '&' if pstr.length > 0
          pstr << (opts['encode_params'] ? set_encode_uri(rand_var) : rand_var)
          pstr << '='
          pstr << (opts['encode_params'] ? set_encode_uri(rand_val) : rand_val)
        end
      end

      opts['vars_post'] = Hash[opts['vars_post'].to_a.shuffle] if (opts['shuffle_post_params'])

      opts['vars_post'].each_pair do |var,val|
        var = var.to_s
        unless val.is_a?(Array)
          val = [val]
        end
        val.each do |v|
          v = v.to_s
          pstr << '&' if pstr.length > 0
          pstr << (opts['encode_params'] ? set_encode_uri(var) : var)
          pstr << '='
          pstr << (opts['encode_params'] ? set_encode_uri(v) : v)
        end
      end

      if opts['vars_form_data'] && opts['vars_form_data'].length > 0
        unless opts['vars_form_data'].is_a?(::Array)
          raise ::ArgumentError, "request_cgi: The provided `form_data` option is not valid. Expected: Array, Got: #{opts['form_data'].class}"
        end

        form_data = Rex::MIME::Message.new
        # Initialize or reuse the previous form data boundary to ensure idempotency
        opts['vars_form_data_boundary'] ||= form_data.bound
        form_data.bound = opts['vars_form_data_boundary']

        opts['vars_form_data'].each do |field_hash|
          # The name of the HTTP form field
          field_name = field_hash.fetch('name', nil)
          unless field_name.is_a?(::String) || field_name == nil
            raise ::ArgumentError, "to_s: The provided field `name` option is not valid. Expected: String, Got: #{field_name.class}"
          end

          mime_type = field_hash.fetch('content_type', nil)
          encoding = field_hash.fetch('encoding', nil)

          file_contents = get_file_data(field_hash['data'])
          filename = field_hash.fetch('filename') { get_filename(field_hash['data']) }

          content_disposition = 'form-data'
          content_disposition << "; name=\"#{field_name}\"" if field_name
          # NOTE: The file name is intentionally unescaped, as exploits such as playsms_filename_exec embed payloads into the file name which shouldn't be escaped
          content_disposition << "; filename=\"#{filename}\"" if filename

          form_data.add_part(file_contents, mime_type, encoding, content_disposition)
        end

        pstr += form_data.to_s
      end

      ctype ||= "multipart/form-data; boundary=#{opts['vars_form_data_boundary']}" if opts['vars_form_data_boundary']
      ctype ||= 'application/x-www-form-urlencoded' if opts['method'] == 'POST'
    else
      if opts['encode']
        qstr = set_encode_uri(qstr)
      end
      uri_str = set_uri
    end

    req = ''
    req << set_method
    req << set_method_uri_spacer()
    req << set_uri_prepend()

    if opts['encode']
      req << set_encode_uri(uri_str)
    else
      req << uri_str
    end


    if (qstr.length > 0)
      req << '?'
      req << qstr
    end

    req << set_path_info
    req << set_uri_append()
    req << set_uri_version_spacer()
    req << set_version

    # Set a default Host header if one wasn't passed in
    unless opts['headers'] && opts['headers'].keys.map(&:downcase).include?('host')
      req << set_host_header
    end

    # If an explicit User-Agent header is set, then use that instead of
    # the default
    unless opts['headers'] && opts['headers'].keys.map(&:downcase).include?('user-agent')
      req << set_agent_header
    end

    # Similar to user-agent, only add an automatic auth header if a
    # manual one hasn't been provided
    unless opts['headers'] && opts['headers'].keys.map(&:downcase).include?('authorization')
      req << set_auth_header
    end

    req << set_cookie_header
    req << set_connection_header
    req << set_extra_headers

    req << set_content_type_header(ctype)
    req << set_content_len_header(pstr.length)
    req << set_chunked_header
    req << opts['raw_headers']
    req << set_body(pstr) unless headers_only

    req
  end

  protected

  def set_uri
    uri_str = opts['uri'].dup
    if (opts['uri_dir_self_reference'])
      uri_str.gsub!('/', '/./')
    end

    if (opts['uri_dir_fake_relative'])
      buf = ""
      uri_str.split('/',-1).each do |part|
        cnt = rand(8)+2
        1.upto(cnt) { |idx|
          buf << "/" + Rex::Text.rand_text_alphanumeric(rand(32)+1)
        }
        buf << ("/.." * cnt)
        buf << "/" + part
      end
      uri_str = buf
    end

    if (opts['uri_full_url'])
      url = opts['ssl'] ? "https://" : "http://"
      url << opts['vhost']
      url << ((opts['port'] == 80) ? "" : ":#{opts['port']}")
      url << uri_str
      url
    else
      uri_str
    end
  end

  def set_encode_uri(str)
    a = str.to_s.dup
    opts['uri_encode_count'].times {
      a = Rex::Text.uri_encode(a, opts['uri_encode_mode'])
    }
    return a
  end

  def set_method
    ret = opts['method'].dup

    if (opts['method_random_valid'])
      ret = ['GET', 'POST', 'HEAD'][rand(3)]
    end

    if (opts['method_random_invalid'])
      ret = Rex::Text.rand_text_alpha(rand(20)+1)
    end

    if (opts['method_random_case'])
      ret = Rex::Text.to_rand_case(ret)
    end

    ret
  end

  def set_method_uri_spacer
    len = opts['pad_method_uri_count'].to_i
    set = " "
    buf = ""

    case opts['pad_method_uri_type']
    when 'tab'
      set = "\t"
    when 'apache'
      set = "\t \x0b\x0c\x0d"
    end

    while(buf.length < len)
      buf << set[ rand(set.length) ]
    end

    return buf
  end

  #
  # Return the padding to place before the uri
  #
  def set_uri_prepend
    prefix = ""

    if (opts['uri_fake_params_start'])
      prefix << '/%3fa=b/../'
    end

    if (opts['uri_fake_end'])
      prefix << '/%20HTTP/1.0/../../'
    end

    prefix
  end

  #
  # Return the HTTP path info
  # TODO:
  #  * Encode path information
  def set_path_info
    opts['path_info'] ? opts['path_info'] : ''
  end

  #
  # Return the padding to place before the uri
  #
  def set_uri_append
    # TODO:
    #  * Support different padding types
    ""
  end

  #
  # Return the spacing between the uri and the version
  #
  def set_uri_version_spacer
    len = opts['pad_uri_version_count'].to_i
    set = " "
    buf = ""

    case opts['pad_uri_version_type']
    when 'tab'
      set = "\t"
    when 'apache'
      set = "\t \x0b\x0c\x0d"
    end

    while(buf.length < len)
      buf << set[ rand(set.length) ]
    end

    return buf
  end

  #
  # Return the HTTP version string
  #
  def set_version
    ret = opts['proto'] + "/" + opts['version']

    if (opts['version_random_valid'])
      ret = opts['proto'] + "/" +  ['1.0', '1.1'][rand(2)]
    end

    if (opts['version_random_invalid'])
      ret = Rex::Text.rand_text_alphanumeric(rand(20)+1)
    end

    ret << "\r\n"
  end

  #
  # Return a formatted header string
  #
  def set_formatted_header(var, val)
    if (self.opts['header_folding'])
      "#{var}:\r\n\t#{val}\r\n"
    else
      "#{var}: #{val}\r\n"
    end
  end

  #
  # Return the HTTP agent header
  #
  def set_agent_header
    opts['agent'] ? set_formatted_header("User-Agent", opts['agent']) : ""
  end

  def set_auth_header
    opts['authorization'] ? set_formatted_header("Authorization", opts['authorization']) : ""
  end

  #
  # Return the HTTP cookie header
  #
  def set_cookie_header
    opts['cookie'] ? set_formatted_header("Cookie", opts['cookie']) : ""
  end

  #
  # Return the HTTP connection header
  #
  def set_connection_header
    opts['connection'] ? set_formatted_header("Connection", opts['connection']) : ""
  end

  #
  # Return the content type header
  #
  def set_content_type_header(ctype)
    ctype ? set_formatted_header("Content-Type", ctype) : ""
  end

  #
  # Return the content length header
  #
  def set_content_len_header(clen)
    if opts['method'] == 'GET' && (clen == 0 || opts['chunked_size'] > 0)
      # This condition only applies to GET because of the specs.
      # RFC-7230:
      # A Content-Length header field is normally sent in a POST
      # request even when the value is 0 (indicating an empty payload body)
      return ''
    elsif opts['headers'] && opts['headers']['Content-Length']
      # If the module has a modified content-length header, respect that by
      # not setting another one.
      return ''
    end
    set_formatted_header("Content-Length", clen)
  end

  #
  # Return the HTTP Host header
  #
  def set_host_header
    return "" if opts['uri_full_url']
    host = opts['vhost']

    # IPv6 addresses must be placed in brackets
    if Rex::Socket.is_ipv6?(host)
      host = "[#{host}]"
    end

    # The port should be appended if non-standard
    if not [80,443].include?(opts['port'])
      host = host + ":#{opts['port']}"
    end

    set_formatted_header("Host", host)
  end

  #
  # Return a string of formatted extra headers
  #
  def set_extra_headers
    buf = ''

    if (opts['pad_fake_headers'])
      1.upto(opts['pad_fake_headers_count'].to_i) do |i|
        buf << set_formatted_header(
          Rex::Text.rand_text_alphanumeric(rand(32)+1),
          Rex::Text.rand_text_alphanumeric(rand(32)+1)
        )
      end
    end

    opts['headers'].each_pair do |var,val|
      buf << set_formatted_header(var, val)
    end

    buf
  end

  def set_chunked_header
    return "" if opts['chunked_size'] == 0
    set_formatted_header('Transfer-Encoding', 'chunked')
  end

  #
  # Return the HTTP separator and body string
  #
  def set_body(bdata)
    return "\r\n" + bdata if opts['chunked_size'] == 0
    str = bdata.dup
    chunked = ''
    while str.size > 0
      chunk = str.slice!(0,rand(opts['chunked_size']) + 1)
      chunked << sprintf("%x", chunk.size) + "\r\n" + chunk + "\r\n"
    end
    "\r\n" + chunked + "0\r\n\r\n"
  end

  def get_file_data(file)
    file.respond_to?('read') ? (file.rewind; contents = file.read; file.rewind; contents) : file.to_s
  end

  def get_filename(data)
    data.is_a?(::Pathname) || data.is_a?(::File) ? ::File.basename(data) : nil
  end

end



end
end
end

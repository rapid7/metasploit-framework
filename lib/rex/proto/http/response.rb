# -*- coding: binary -*-
require 'cgi'
require 'uri'
require 'rex/proto/http'
require 'nokogiri'
require 'rkelly'

module Rex
module Proto
module Http

###
#
# HTTP response class.
#
###
class Response < Packet

  ##
  #
  # Builtin response class wrappers.
  #
  ##

  #
  # HTTP 200/OK response class wrapper.
  #
  class OK < Response
    def initialize(message = 'OK', proto = DefaultProtocol)
      super(200, message, proto)
    end
  end

  #
  # HTTP 404/File not found response class wrapper.
  #
  class E404 < Response
    def initialize(message = 'File not found', proto = DefaultProtocol)
      super(404, message, proto)
    end
  end

  #
  # Constructage of the HTTP response with the supplied code, message, and
  # protocol.
  #
  def initialize(code = 200, message = 'OK', proto = DefaultProtocol)
    super()

    self.code    = code.to_i
    self.message = message
    self.proto   = proto

    # Default responses to auto content length on
    self.auto_cl = true

    # default chunk sizes (if chunked is used)
    self.chunk_min_size = 1
    self.chunk_max_size = 10

    # 100 continue counter
    self.count_100 = 0
  end

  #
  # Gets cookies from the Set-Cookie header in a format to be used
  # in the 'cookie' send_request field
  #
  def get_cookies
    cookies = ""
    if (self.headers.include?('Set-Cookie'))
      set_cookies = self.headers['Set-Cookie']
      key_vals = set_cookies.scan(/\s?([^, ;]+?)=([^, ;]*?)[;,]/)
      key_vals.each do |k, v|
        # Dont downcase actual cookie name as may be case sensitive
        name = k.downcase
        next if name == 'path'
        next if name == 'expires'
        next if name == 'domain'
        next if name == 'max-age'
        cookies << "#{k}=#{v}; "
      end
    end

    return cookies.strip
  end

  #
  # Gets cookies from the Set-Cookie header in a parsed format
  #
  def get_cookies_parsed
    if (self.headers.include?('Set-Cookie'))
      ret = CGI::Cookie::parse(self.headers['Set-Cookie'])
    else
      ret = {}
    end
    ret
  end


  # Returns a parsed HTML document.
  # Instead of using regexes to parse the HTML body, you should use this and use the Nokogiri API.
  #
  # @see http://www.nokogiri.org/
  # @return [Nokogiri::HTML::Document]
  def get_html_document
    Nokogiri::HTML(self.body)
  end

  # Returns a parsed XML document.
  # Instead of using regexes to parse the XML body, you should use this and use the Nokogiri API.
  #
  # @see http://www.nokogiri.org/
  # @return [Nokogiri::XML::Document]
  def get_xml_document
    Nokogiri::XML(self.body)
  end

  # Returns a parsed json document.
  # Instead of using regexes to parse the JSON body, you should use this.
  #
  # @return [Hash]
  def get_json_document
    json = {}

    begin
      json = JSON.parse(self.body)
    rescue JSON::ParserError => e
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
    end

    json
  end

  # Returns meta tags.
  # You will probably want to use this the web app's version info (or other stuff) can be found
  # in the metadata.
  #
  # @return [Array<Nokogiri::XML::Element>]
  def get_html_meta_elements
    n = get_html_document
    n.search('//meta')
  end

  # Returns parsed JavaScript blocks.
  # The parsed version is a RKelly object that allows you to be able do advanced parsing.
  #
  # @see https://github.com/tenderlove/rkelly
  # @return [Array<RKelly::Nodes::SourceElementsNode>]
  def get_html_scripts
    n = get_html_document
    rkelly = RKelly::Parser.new
    n.search('//script').map { |s| rkelly.parse(s.text) }
  end


  # Returns a collection of found hidden inputs
  #
  # @return [Array<Hash>] An array, each element represents a form that contains a hash of found hidden inputs
  #  * 'name' [String] The hidden input's original name. The value is the hidden input's original value.
  # @example
  #  res = send_request_cgi('uri'=>'/')
  #  inputs = res.get_hidden_inputs
  #  session_id = inputs[0]['sessionid'] # The first form's 'sessionid' hidden input
  def get_hidden_inputs
    forms = []
    noko = get_html_document
    noko.search("form").each_entry do |form|
      found_inputs = {}
      form.search("input").each_entry do |input|
        input_type = input.attributes['type'] ? input.attributes['type'].value : ''
        next if input_type !~ /hidden/i

        input_name = input.attributes['name'] ? input.attributes['name'].value : ''
        input_value = input.attributes['value'] ? input.attributes['value'].value : ''
        found_inputs[input_name] = input_value unless input_name.empty?
      end
      forms << found_inputs unless found_inputs.empty?
    end

    forms
  end

  #
  # Updates the various parts of the HTTP response command string.
  #
  def update_cmd_parts(str)
    if (md = str.match(/HTTP\/(.+?)\s+(\d+)\s?(.+?)\r?\n?$/))
      self.message = md[3].gsub(/\r/, '')
      self.code    = md[2].to_i
      self.proto   = md[1]
    else
      raise RuntimeError, "Invalid response command string", caller
    end

    check_100()
  end

  #
  # Allow 100 Continues to be ignored by the caller
  #
  def check_100
    # If this was a 100 continue with no data, reset
    if self.code == 100 and (self.body_bytes_left == -1 or self.body_bytes_left == 0) and self.count_100 < 5
      self.reset_except_queue
      self.count_100 += 1
    end
  end

  # Answers if the response is a redirection one.
  #
  # @return [Boolean] true if the response is a redirection, false otherwise.
  def redirect?
    [301, 302, 303, 307, 308].include?(code)
  end

  # Provides the uri of the redirection location.
  #
  # @return [URI] the uri of the redirection location.
  # @return [nil] if the response hasn't a Location header or it isn't a valid uri.
  def redirection
    begin
      URI(headers['Location'])
    rescue ::URI::InvalidURIError
      nil
    end
  end

  #
  # Returns the response based command string.
  #
  def cmd_string
    "HTTP\/#{proto} #{code}#{(message and message.length > 0) ? ' ' + message : ''}\r\n"
  end

  #
  # Used to store a copy of the original request
  #
  attr_accessor :request

  #
  # Host address:port associated with this request/response
  #
  attr_accessor :peerinfo

  attr_accessor :code
  attr_accessor :message
  attr_accessor :proto
  attr_accessor :count_100
end

end
end
end

# -*- coding: binary -*-

##
# This module contains helper functions for parsing and loading malleable
# C2 profiles into ruby objects.
##

require 'strscan'
require 'rex/post/meterpreter/packet'

# Handle escape sequences in the strings provided by the c2 profile
class String
  def from_c2_string_value
    # Support substitution of a subset of escape characters:
    # \r, \t, \n, \\, \x..
    # Not supporting \u at this point.
    # We do in a single regex and parse each as we go, as this avoids the
    # potential for double-encoding.
    self.gsub(/\\(x(..)|r|n|t|\\)/) {|b|
      case b[1]
      when 'x'
        [b[2, 4].to_i(16)].pack('C')
      when 'r'
        "\r"
      when 't'
        "\t"
      when 'n'
        "\n"
      when '\\'
        "\\"
      end
    }
  end
end

module Msf::Payload::MalleableC2

  MET = Rex::Post::Meterpreter

  class Token
    attr_reader :type, :value

    def initialize(type, value)
      @type = type
      @value = value
    end
  end

  class Lexer

    attr_reader :tokens

    BLOCK_KEYWORDS = %w[
      client
      http-get
      http-post
      http-stager
      https-certificate
      id
      metadata
      output
      server
      stage
      transform-x64
      transform-x86
    ]

    OTHER_KEYWORDS = %w[
      add
      append
      base64
      base64url
      dns
      encode_hex
      header
      hostport
      mask
      netbios
      netbiosu
      parameter
      prepend
      print
      remove
      set
      string
      stringw
      strrep
      transform
      unset
      uri
      uri-append
      uri-query
      xor
    ]

    def initialize(file)
      @tokens = []
      tokenize(File.read(file))
    end

    def is_block_keyword?(word)
      BLOCK_KEYWORDS.include?(word)
    end

    def tokenize(text)
      scanner = StringScanner.new(text)

      until scanner.eos?
        if scanner.scan(/\s+/)
          # blank line
          next
        elsif scanner.scan(/^\s*#.*$/)
          # comment
          next
        elsif scanner.scan(/\"(\\.|[^"])*\"/)
          #@tokens << Token.new(:string, scanner.matched[1..-2])
          @tokens << Token.new(:string, scanner.matched[1..-2])
        elsif scanner.scan(/[a-zA-Z0-9_\-\.\/]+/)
          word = scanner.matched
          type = BLOCK_KEYWORDS.union(OTHER_KEYWORDS).include?(word) ? :keyword : :identifier
          @tokens << Token.new(type, word)
        elsif scanner.scan(/[{};]/)
          @tokens << Token.new(:symbol, scanner.matched)
        else
          raise "Unexpected token near: #{scanner.peek(20)}"
        end
      end
    end
  end

  class ParsedProfile
    attr_accessor :sets, :sections

    def initialize
      @sets = []
      @sections = []
    end

    def method_missing(name, *args)
      name = name.to_s.gsub('_', '-')
      get_section(name) || get_set(name)
    end

    def get_set(key)
      val = @sets.find {|s| s.key == key.downcase}&.value
      if block_given? && !val.nil?
        yield(val)
      end
      val
    end

    def get_section(name)
      sec = @sections.find {|s| s.name == name.downcase}
      if block_given? && !sec.nil?
        yield(sec)
      end
      sec
    end

    def uris
      base_uri = self.get_set('uri')
      get_uri = nil
      post_uri = nil

      self.get_section('http-get') {|http_get|
        get_uri = http_get.get_set('uri')
      }
      self.get_section('http-post') {|http_post|
        post_uri = http_post.get_set('uri')
      }

      [base_uri, get_uri, post_uri].compact
    end

    def wrap_outbound_get(raw_bytes)
      prepends = self.http_get&.server&.output&.prepend || []
      prefix = prepends.reverse.map {|p| p.args[0]}.join('')
      appends = self.http_get&.server&.output&.append || []
      suffix = appends.map {|p| p.args[0]}.join('')
      prefix + raw_bytes + suffix
    end

    def unwrap_inbound_post(raw_bytes)
      prepends = self.http_post&.client&.output&.prepend || []
      prefix = prepends.reverse.map {|p| p.args[0]}.join('')
      unless prefix.empty? || (raw_bytes[0, prefix.length] <=> prefix) != 0
        raw_bytes = raw_bytes[prefix.length, raw_bytes.length]
      end

      appends = self.http_post&.client&.output&.append || []
      suffix = appends.map {|p| p.args[0]}.join('')
      unless suffix.empty? || (raw_bytes[-suffix.length, raw_bytes.length] <=> suffix) != 0
        raw_bytes = raw_bytes[0, raw_bytes.length - suffix.length]
      end
      raw_bytes
    end

    def to_tlv
      tlv = MET::GroupTlv.new(MET::TLV_TYPE_C2)

      self.get_set('useragent') {|ua| tlv.add_tlv(MET::TLV_TYPE_C2_UA, ua)}
      c2_uri = self.get_set('uri')

      self.get_section('http-get') {|http_get|
        get_tlv = MET::GroupTlv.new(MET::TLV_TYPE_C2_GET)
        get_uri = http_get.get_set('uri') || c2_uri
        http_get.get_section('client') {|client|
          self.add_http_tlv(get_uri, client, get_tlv)

          prepends = self.http_get&.server&.output&.prepend || []
          prefix = prepends.reverse.map {|p| p.args[0]}.join('')
          get_tlv.add_tlv(MET::TLV_TYPE_C2_SKIP_COUNT, prefix.length) unless prefix.length == 0

          client.get_section('metadata') {|meta|
            enc_flags = 0
            enc_flags |= MET::C2_ENCODING_FLAG_B64 if meta.has_directive('base64')
            enc_flags |= MET::C2_ENCODING_FLAG_B64URL if meta.has_directive('base64url')

            get_tlv.add_tlv(MET::TLV_TYPE_C2_ENC, enc_flags) if enc_flags != 0
            get_tlv.add_tlv(MET::TLV_TYPE_C2_UUID_GET, meta.get_directive('parameter')[0].args[0]) if meta.has_directive('parameter')
            get_tlv.add_tlv(MET::TLV_TYPE_C2_UUID_HEADER, meta.get_directive('header')[0].args[0]) if meta.has_directive('header')
            # assume uri-append for POST otherwise.
          }
        }

        tlv.tlvs << get_tlv
      }

      self.get_section('http-post') {|http_post|
        post_tlv = MET::GroupTlv.new(MET::TLV_TYPE_C2_POST)
        post_uri = http_post.get_set('uri') || c2_uri
        http_post.get_section('client') {|client|
          self.add_http_tlv(post_uri, client, post_tlv)

          prepends = self.http_get&.server&.output&.prepend || []
          prefix = prepends.reverse.map {|p| p.args[0]}.join('')
          post_tlv.add_tlv(MET::TLV_TYPE_C2_SKIP_COUNT, prefix.length) unless prefix.length == 0

          client.get_section('output') {|client_output|
            enc_flags = 0
            enc_flags |= MET::C2_ENCODING_FLAG_B64 if client_output.has_directive('base64')
            enc_flags |= MET::C2_ENCODING_FLAG_B64URL if client_output.has_directive('base64url')

            post_tlv.add_tlv(MET::TLV_TYPE_C2_ENC, enc_flags) if enc_flags != 0

            prepend_data = client_output.get_directive('prepend').map{|d|d.args[0]}.reverse.join("")
            post_tlv.add_tlv(MET::TLV_TYPE_C2_PREFIX, prepend_data) unless prepend_data.empty?
            append_data = client_output.get_directive('append').map{|d|d.args[0]}.join("")
            post_tlv.add_tlv(MET::TLV_TYPE_C2_SUFFIX, append_data) unless append_data.empty?
          }

          client.get_section('id') {|client_id|
            post_tlv.add_tlv(MET::TLV_TYPE_C2_UUID_GET, client_id.get_directive('parameter')[0].args[0]) if client_id.has_directive('parameter')
            post_tlv.add_tlv(MET::TLV_TYPE_C2_UUID_HEADER, client_id.get_directive('header')[0].args[0]) if client_id.has_directive('header')
            # assume uri-append for POST otherwise given that we always put the TLV payload in the body?
            # TODO: add support for adding a form rather than just a payload body?
          }
        }

        tlv.tlvs << post_tlv
      }

      tlv
    end

    def add_http_tlv(base_uri, section, group_tlv)
      section.get_set('useragent') {|v| group_tlv.add_tlv(MET::TLV_TYPE_C2_UA, v)}

      self.add_uri(base_uri, section, group_tlv)
      self.add_header(section, group_tlv)
    end

    def add_header(section, group_tlv)
      headers = section.get_directive('header').map {|dir| "#{dir.args[0]}: #{dir.args[1]}"}.join("\r\n")
      group_tlv.add_tlv(MET::TLV_TYPE_C2_HEADERS, headers) unless headers.empty?
      headers
    end

    def add_uri(base_uri, section, group_tlv)
      uri = base_uri || ""
      query_string = section.get_directive('parameter').map {|dir| "#{dir.args[0]}=#{URI.encode_uri_component(dir.args[1])}" }.join("&")
      unless query_string.empty?
        uri << "?"
        uri << query_string
      end
      group_tlv.add_tlv(MET::TLV_TYPE_C2_URI, uri) unless uri.empty?
      uri
    end
  end

  class ParsedSet
    attr_accessor :key, :value
    def initialize(key, value)
      @key = key.downcase
      @value = value.from_c2_string_value
    end
  end

  class ParsedSection
    attr_accessor :name, :entries, :sections
    def initialize(name)
      @name = name.downcase
      @entries = []
      @sections = []
    end

    def method_missing(name, *args)
      name = name.to_s.gsub('_', '-')
      get_section(name) || get_directive(name) || get_set(name)
    end

    def get_set(key)
      val = @entries.find {|s| s.kind_of?(ParsedSet) && s.key == key.downcase}&.value
      if block_given? && !val.nil?
        yield(val)
      end
      val
    end

    def get_directive(type)
      # there can be multiple instances of the same directive type so we have
      # to return an array instead of a single instance
      @entries.find_all {|d| d.kind_of?(ParsedDirective) && d.type == type.downcase}
    end

    def has_directive(type)
      @entries.find_all {|d| d.kind_of?(ParsedDirective) && d.type == type.downcase}.length > 0
    end

    def get_section(name)
      sec = @sections.find {|s| s.name == name.downcase}
      if block_given? && !sec.nil?
        yield(sec)
      end
      sec
    end
  end

  class ParsedDirective
    attr_accessor :type, :args
    def initialize(type, args)
      @type = type.downcase
      @args = args.map {|a| a.from_c2_string_value}
    end
  end

  class Parser
    attr_reader :lexer

    def initialize
      @lexer = nil
    end

    def parse(file)
      @lexer = Lexer.new(file)
      @index = 0
      profile = ParsedProfile.new

      while current_token
        if match_keyword('set')
          profile.sets << parse_set
        elsif current_token.type == :keyword && @lexer.is_block_keyword?(current_token.value)
          profile.sections << parse_section
        else
          raise "Unexpected token at tope level:  #{current_token.type}=#{current_token.value}"
        end
      end

      #@lexer = nil
      profile
    end

    def parse_set
      expect_keyword('set')
      key = expect([:identifier, :keyword]).value
      value = expect(:string).value
      expect_symbol(';')
      ParsedSet.new(key, value)
    end

    def parse_section
      name = expect(:keyword).value
      expect_symbol('{')
      section = ParsedSection.new(name)

      while !match_symbol('}') && current_token
        if match_keyword('set')
          section.entries << parse_set
        elsif current_token.type == :keyword
          if @lexer.is_block_keyword?(current_token.value)
            section.sections << parse_section
          else
            section.entries << parse_directive
          end
        else
          raise "Unexpected content in block #{name}: #{current_token.value}"
        end
      end

      expect_symbol('}')
      section
    end

    def parse_directive
      type = expect(:keyword).value
      args = []
      while current_token && !match_symbol(';')
        if [:string, :identifier, :keyword].include?(current_token.type)
          args << current_token.value
          next_token
        else
          break
        end
      end
      expect_symbol(';')
      ParsedDirective.new(type, args)
    end

    def current_token
      @lexer.tokens[@index]
    end

    def next_token
      @index += 1
      current_token
    end

    def expect(types)
      token = current_token
      types = [types] unless types.kind_of?(Array)
      raise "Expected #{types.inspect}, got #{token&.type}=#{token&.value}" unless token && types.include?(token.type)
      next_token
      token
    end

    def expect_keyword(word)
      token = current_token
      raise "Expected keyword '#{word}', got #{token&.value}" unless token && token.type == :keyword && token.value == word
      next_token
      token
    end

    def expect_symbol(symbol)
      token = current_token
      raise "Expected symbol '#{symbol}', got #{token&.value}" unless token && token.type == :symbol && token.value == symbol
      next_token
      token
    end

    def match_keyword(word)
      token = current_token
      token && token.type == :keyword && token.value == word
    end

    def match_symbol(symbol)
      token = current_token
      token && token.type == :symbol && token.value == symbol
    end
  end

end

# -*- encoding: binary -*-
require 'fileutils'
require 'set'
require 'tempfile'
require 'rack/multipart'
require 'time'

major, minor, patch = RUBY_VERSION.split('.').map { |v| v.to_i }

if major == 1 && minor < 9
  require 'rack/backports/uri/common_18'
elsif major == 1 && minor == 9 && patch == 2 && RUBY_PATCHLEVEL <= 328 && RUBY_ENGINE != 'jruby'
  require 'rack/backports/uri/common_192'
elsif major == 1 && minor == 9 && patch == 3 && RUBY_PATCHLEVEL < 125
  require 'rack/backports/uri/common_193'
else
  require 'uri/common'
end

module Rack
  # Rack::Utils contains a grab-bag of useful methods for writing web
  # applications adopted from all kinds of Ruby libraries.

  module Utils
    # ParameterTypeError is the error that is raised when incoming structural
    # parameters (parsed by parse_nested_query) contain conflicting types.
    class ParameterTypeError < TypeError; end

    # InvalidParameterError is the error that is raised when incoming structural
    # parameters (parsed by parse_nested_query) contain invalid format or byte
    # sequence.
    class InvalidParameterError < ArgumentError; end

    # URI escapes. (CGI style space to +)
    def escape(s)
      URI.encode_www_form_component(s)
    end
    module_function :escape

    # Like URI escaping, but with %20 instead of +. Strictly speaking this is
    # true URI escaping.
    def escape_path(s)
      escape(s).gsub('+', '%20')
    end
    module_function :escape_path

    # Unescapes a URI escaped string with +encoding+. +encoding+ will be the
    # target encoding of the string returned, and it defaults to UTF-8
    if defined?(::Encoding)
      def unescape(s, encoding = Encoding::UTF_8)
        URI.decode_www_form_component(s, encoding)
      end
    else
      def unescape(s, encoding = nil)
        URI.decode_www_form_component(s, encoding)
      end
    end
    module_function :unescape

    DEFAULT_SEP = /[&;] */n

    class << self
      attr_accessor :key_space_limit
      attr_accessor :param_depth_limit
      attr_accessor :multipart_part_limit
    end

    # The default number of bytes to allow parameter keys to take up.
    # This helps prevent a rogue client from flooding a Request.
    self.key_space_limit = 65536

    # Default depth at which the parameter parser will raise an exception for
    # being too deep.  This helps prevent SystemStackErrors
    self.param_depth_limit = 100

    # The maximum number of parts a request can contain. Accepting too many part
    # can lead to the server running out of file handles.
    # Set to `0` for no limit.
    # FIXME: RACK_MULTIPART_LIMIT was introduced by mistake and it will be removed in 1.7.0
    self.multipart_part_limit = (ENV['RACK_MULTIPART_PART_LIMIT'] || ENV['RACK_MULTIPART_LIMIT'] || 128).to_i

    # Stolen from Mongrel, with some small modifications:
    # Parses a query string by breaking it up at the '&'
    # and ';' characters.  You can also use this to parse
    # cookies by changing the characters used in the second
    # parameter (which defaults to '&;').
    def parse_query(qs, d = nil, &unescaper)
      unescaper ||= method(:unescape)

      params = KeySpaceConstrainedParams.new

      (qs || '').split(d ? /[#{d}] */n : DEFAULT_SEP).each do |p|
        next if p.empty?
        k, v = p.split('=', 2).map(&unescaper)

        if cur = params[k]
          if cur.class == Array
            params[k] << v
          else
            params[k] = [cur, v]
          end
        else
          params[k] = v
        end
      end

      return params.to_params_hash
    end
    module_function :parse_query

    # parse_nested_query expands a query string into structural types. Supported
    # types are Arrays, Hashes and basic value types. It is possible to supply
    # query strings with parameters of conflicting types, in this case a
    # ParameterTypeError is raised. Users are encouraged to return a 400 in this
    # case.
    def parse_nested_query(qs, d = nil)
      params = KeySpaceConstrainedParams.new

      (qs || '').split(d ? /[#{d}] */n : DEFAULT_SEP).each do |p|
        k, v = p.split('=', 2).map { |s| unescape(s) }

        normalize_params(params, k, v)
      end

      return params.to_params_hash
    rescue ArgumentError => e
      raise InvalidParameterError, e.message
    end
    module_function :parse_nested_query

    # normalize_params recursively expands parameters into structural types. If
    # the structural types represented by two different parameter names are in
    # conflict, a ParameterTypeError is raised.
    def normalize_params(params, name, v = nil, depth = Utils.param_depth_limit)
      raise RangeError if depth <= 0

      name =~ %r(\A[\[\]]*([^\[\]]+)\]*)
      k = $1 || ''
      after = $' || ''

      return if k.empty?

      if after == ""
        params[k] = v
      elsif after == "["
        params[name] = v
      elsif after == "[]"
        params[k] ||= []
        raise ParameterTypeError, "expected Array (got #{params[k].class.name}) for param `#{k}'" unless params[k].is_a?(Array)
        params[k] << v
      elsif after =~ %r(^\[\]\[([^\[\]]+)\]$) || after =~ %r(^\[\](.+)$)
        child_key = $1
        params[k] ||= []
        raise ParameterTypeError, "expected Array (got #{params[k].class.name}) for param `#{k}'" unless params[k].is_a?(Array)
        if params_hash_type?(params[k].last) && !params[k].last.key?(child_key)
          normalize_params(params[k].last, child_key, v, depth - 1)
        else
          params[k] << normalize_params(params.class.new, child_key, v, depth - 1)
        end
      else
        params[k] ||= params.class.new
        raise ParameterTypeError, "expected Hash (got #{params[k].class.name}) for param `#{k}'" unless params_hash_type?(params[k])
        params[k] = normalize_params(params[k], after, v, depth - 1)
      end

      return params
    end
    module_function :normalize_params

    def params_hash_type?(obj)
      obj.kind_of?(KeySpaceConstrainedParams) || obj.kind_of?(Hash)
    end
    module_function :params_hash_type?

    def build_query(params)
      params.map { |k, v|
        if v.class == Array
          build_query(v.map { |x| [k, x] })
        else
          v.nil? ? escape(k) : "#{escape(k)}=#{escape(v)}"
        end
      }.join("&")
    end
    module_function :build_query

    def build_nested_query(value, prefix = nil)
      case value
      when Array
        value.map { |v|
          build_nested_query(v, "#{prefix}[]")
        }.join("&")
      when Hash
        value.map { |k, v|
          build_nested_query(v, prefix ? "#{prefix}[#{escape(k)}]" : escape(k))
        }.reject(&:empty?).join('&')
      when nil
        prefix
      else
        raise ArgumentError, "value must be a Hash" if prefix.nil?
        "#{prefix}=#{escape(value)}"
      end
    end
    module_function :build_nested_query

    def q_values(q_value_header)
      q_value_header.to_s.split(/\s*,\s*/).map do |part|
        value, parameters = part.split(/\s*;\s*/, 2)
        quality = 1.0
        if md = /\Aq=([\d.]+)/.match(parameters)
          quality = md[1].to_f
        end
        [value, quality]
      end
    end
    module_function :q_values

    def best_q_match(q_value_header, available_mimes)
      values = q_values(q_value_header)

      matches = values.map do |req_mime, quality|
        match = available_mimes.find { |am| Rack::Mime.match?(am, req_mime) }
        next unless match
        [match, quality]
      end.compact.sort_by do |match, quality|
        (match.split('/', 2).count('*') * -10) + quality
      end.last
      matches && matches.first
    end
    module_function :best_q_match

    ESCAPE_HTML = {
      "&" => "&amp;",
      "<" => "&lt;",
      ">" => "&gt;",
      "'" => "&#x27;",
      '"' => "&quot;",
      "/" => "&#x2F;"
    }
    if //.respond_to?(:encoding)
      ESCAPE_HTML_PATTERN = Regexp.union(*ESCAPE_HTML.keys)
    else
      # On 1.8, there is a kcode = 'u' bug that allows for XSS otherwise
      # TODO doesn't apply to jruby, so a better condition above might be preferable?
      ESCAPE_HTML_PATTERN = /#{Regexp.union(*ESCAPE_HTML.keys)}/n
    end

    # Escape ampersands, brackets and quotes to their HTML/XML entities.
    def escape_html(string)
      string.to_s.gsub(ESCAPE_HTML_PATTERN){|c| ESCAPE_HTML[c] }
    end
    module_function :escape_html

    def select_best_encoding(available_encodings, accept_encoding)
      # http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html

      expanded_accept_encoding =
        accept_encoding.map { |m, q|
          if m == "*"
            (available_encodings - accept_encoding.map { |m2, _| m2 }).map { |m2| [m2, q] }
          else
            [[m, q]]
          end
        }.inject([]) { |mem, list|
          mem + list
        }

      encoding_candidates = expanded_accept_encoding.sort_by { |_, q| -q }.map { |m, _| m }

      unless encoding_candidates.include?("identity")
        encoding_candidates.push("identity")
      end

      expanded_accept_encoding.each { |m, q|
        encoding_candidates.delete(m) if q == 0.0
      }

      return (encoding_candidates & available_encodings)[0]
    end
    module_function :select_best_encoding

    def set_cookie_header!(header, key, value)
      case value
      when Hash
        domain  = "; domain="  + value[:domain]       if value[:domain]
        path    = "; path="    + value[:path]         if value[:path]
        max_age = "; max-age=" + value[:max_age].to_s if value[:max_age]
        # There is an RFC mess in the area of date formatting for Cookies. Not
        # only are there contradicting RFCs and examples within RFC text, but
        # there are also numerous conflicting names of fields and partially
        # cross-applicable specifications.
        #
        # These are best described in RFC 2616 3.3.1. This RFC text also
        # specifies that RFC 822 as updated by RFC 1123 is preferred. That is a
        # fixed length format with space-date delimeted fields.
        #
        # See also RFC 1123 section 5.2.14.
        #
        # RFC 6265 also specifies "sane-cookie-date" as RFC 1123 date, defined
        # in RFC 2616 3.3.1. RFC 6265 also gives examples that clearly denote
        # the space delimited format. These formats are compliant with RFC 2822.
        #
        # For reference, all involved RFCs are:
        # RFC 822
        # RFC 1123
        # RFC 2109
        # RFC 2616
        # RFC 2822
        # RFC 2965
        # RFC 6265
        expires = "; expires=" +
          rfc2822(value[:expires].clone.gmtime) if value[:expires]
        secure = "; secure"  if value[:secure]
        httponly = "; HttpOnly" if (value.key?(:httponly) ? value[:httponly] : value[:http_only])
        same_site =
          case value[:same_site]
          when false, nil
            nil
          when :lax, 'Lax', :Lax
            '; SameSite=Lax'.freeze
          when true, :strict, 'Strict', :Strict
            '; SameSite=Strict'.freeze
          else
            raise ArgumentError, "Invalid SameSite value: #{value[:same_site].inspect}"
          end
        value = value[:value]
      end
      value = [value] unless Array === value
      cookie = escape(key) + "=" +
        value.map { |v| escape v }.join("&") +
        "#{domain}#{path}#{max_age}#{expires}#{secure}#{httponly}#{same_site}"

      case header["Set-Cookie"]
      when nil, ''
        header["Set-Cookie"] = cookie
      when String
        header["Set-Cookie"] = [header["Set-Cookie"], cookie].join("\n")
      when Array
        header["Set-Cookie"] = (header["Set-Cookie"] + [cookie]).join("\n")
      end

      nil
    end
    module_function :set_cookie_header!

    def delete_cookie_header!(header, key, value = {})
      case header["Set-Cookie"]
      when nil, ''
        cookies = []
      when String
        cookies = header["Set-Cookie"].split("\n")
      when Array
        cookies = header["Set-Cookie"]
      end

      cookies.reject! { |cookie|
        if value[:domain]
          cookie =~ /\A#{escape(key)}=.*domain=#{value[:domain]}/
        elsif value[:path]
          cookie =~ /\A#{escape(key)}=.*path=#{value[:path]}/
        else
          cookie =~ /\A#{escape(key)}=/
        end
      }

      header["Set-Cookie"] = cookies.join("\n")

      set_cookie_header!(header, key,
                 {:value => '', :path => nil, :domain => nil,
                   :max_age => '0',
                   :expires => Time.at(0) }.merge(value))

      nil
    end
    module_function :delete_cookie_header!

    # Return the bytesize of String; uses String#size under Ruby 1.8 and
    # String#bytesize under 1.9.
    if ''.respond_to?(:bytesize)
      def bytesize(string)
        string.bytesize
      end
    else
      def bytesize(string)
        string.size
      end
    end
    module_function :bytesize

    def rfc2822(time)
      time.rfc2822
    end
    module_function :rfc2822

    # Modified version of stdlib time.rb Time#rfc2822 to use '%d-%b-%Y' instead
    # of '% %b %Y'.
    # It assumes that the time is in GMT to comply to the RFC 2109.
    #
    # NOTE: I'm not sure the RFC says it requires GMT, but is ambiguous enough
    # that I'm certain someone implemented only that option.
    # Do not use %a and %b from Time.strptime, it would use localized names for
    # weekday and month.
    #
    def rfc2109(time)
      wday = Time::RFC2822_DAY_NAME[time.wday]
      mon = Time::RFC2822_MONTH_NAME[time.mon - 1]
      time.strftime("#{wday}, %d-#{mon}-%Y %H:%M:%S GMT")
    end
    module_function :rfc2109

    # Parses the "Range:" header, if present, into an array of Range objects.
    # Returns nil if the header is missing or syntactically invalid.
    # Returns an empty array if none of the ranges are satisfiable.
    def byte_ranges(env, size)
      # See <http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.35>
      http_range = env['HTTP_RANGE']
      return nil unless http_range && http_range =~ /bytes=([^;]+)/
      ranges = []
      $1.split(/,\s*/).each do |range_spec|
        return nil  unless range_spec =~ /(\d*)-(\d*)/
        r0,r1 = $1, $2
        if r0.empty?
          return nil  if r1.empty?
          # suffix-byte-range-spec, represents trailing suffix of file
          r0 = size - r1.to_i
          r0 = 0  if r0 < 0
          r1 = size - 1
        else
          r0 = r0.to_i
          if r1.empty?
            r1 = size - 1
          else
            r1 = r1.to_i
            return nil  if r1 < r0  # backwards range is syntactically invalid
            r1 = size-1  if r1 >= size
          end
        end
        ranges << (r0..r1)  if r0 <= r1
      end
      ranges
    end
    module_function :byte_ranges

    # Constant time string comparison.
    #
    # NOTE: the values compared should be of fixed length, such as strings
    # that have already been processed by HMAC. This should not be used
    # on variable length plaintext strings because it could leak length info
    # via timing attacks.
    def secure_compare(a, b)
      return false unless bytesize(a) == bytesize(b)

      l = a.unpack("C*")

      r, i = 0, -1
      b.each_byte { |v| r |= v ^ l[i+=1] }
      r == 0
    end
    module_function :secure_compare

    # Context allows the use of a compatible middleware at different points
    # in a request handling stack. A compatible middleware must define
    # #context which should take the arguments env and app. The first of which
    # would be the request environment. The second of which would be the rack
    # application that the request would be forwarded to.
    class Context
      attr_reader :for, :app

      def initialize(app_f, app_r)
        raise 'running context does not respond to #context' unless app_f.respond_to? :context
        @for, @app = app_f, app_r
      end

      def call(env)
        @for.context(env, @app)
      end

      def recontext(app)
        self.class.new(@for, app)
      end

      def context(env, app=@app)
        recontext(app).call(env)
      end
    end

    # A case-insensitive Hash that preserves the original case of a
    # header when set.
    class HeaderHash < Hash
      def self.new(hash={})
        HeaderHash === hash ? hash : super(hash)
      end

      def initialize(hash={})
        super()
        @names = {}
        hash.each { |k, v| self[k] = v }
      end

      def each
        super do |k, v|
          yield(k, v.respond_to?(:to_ary) ? v.to_ary.join("\n") : v)
        end
      end

      def to_hash
        hash = {}
        each { |k,v| hash[k] = v }
        hash
      end

      def [](k)
        super(k) || super(@names[k.downcase])
      end

      def []=(k, v)
        canonical = k.downcase
        delete k if @names[canonical] && @names[canonical] != k # .delete is expensive, don't invoke it unless necessary
        @names[k] = @names[canonical] = k
        super k, v
      end

      def delete(k)
        canonical = k.downcase
        result = super @names.delete(canonical)
        @names.delete_if { |name,| name.downcase == canonical }
        result
      end

      def include?(k)
        @names.include?(k) || @names.include?(k.downcase)
      end

      alias_method :has_key?, :include?
      alias_method :member?, :include?
      alias_method :key?, :include?

      def merge!(other)
        other.each { |k, v| self[k] = v }
        self
      end

      def merge(other)
        hash = dup
        hash.merge! other
      end

      def replace(other)
        clear
        other.each { |k, v| self[k] = v }
        self
      end
    end

    class KeySpaceConstrainedParams
      def initialize(limit = Utils.key_space_limit)
        @limit  = limit
        @size   = 0
        @params = {}
      end

      def [](key)
        @params[key]
      end

      def []=(key, value)
        @size += key.size if key && !@params.key?(key)
        raise RangeError, 'exceeded available parameter key space' if @size > @limit
        @params[key] = value
      end

      def key?(key)
        @params.key?(key)
      end

      def to_params_hash
        hash = @params
        hash.keys.each do |key|
          value = hash[key]
          if value.kind_of?(self.class)
            if value.object_id == self.object_id
              hash[key] = hash
            else
              hash[key] = value.to_params_hash
            end
          elsif value.kind_of?(Array)
            value.map! {|x| x.kind_of?(self.class) ? x.to_params_hash : x}
          end
        end
        hash
      end
    end

    # Every standard HTTP code mapped to the appropriate message.
    # Generated with:
    # curl -s https://www.iana.org/assignments/http-status-codes/http-status-codes-1.csv | \
    #   ruby -ne 'm = /^(\d{3}),(?!Unassigned|\(Unused\))([^,]+)/.match($_) and \
    #             puts "#{m[1]} => \x27#{m[2].strip}\x27,"'
    HTTP_STATUS_CODES = {
      100 => 'Continue',
      101 => 'Switching Protocols',
      102 => 'Processing',
      200 => 'OK',
      201 => 'Created',
      202 => 'Accepted',
      203 => 'Non-Authoritative Information',
      204 => 'No Content',
      205 => 'Reset Content',
      206 => 'Partial Content',
      207 => 'Multi-Status',
      208 => 'Already Reported',
      226 => 'IM Used',
      300 => 'Multiple Choices',
      301 => 'Moved Permanently',
      302 => 'Found',
      303 => 'See Other',
      304 => 'Not Modified',
      305 => 'Use Proxy',
      307 => 'Temporary Redirect',
      308 => 'Permanent Redirect',
      400 => 'Bad Request',
      401 => 'Unauthorized',
      402 => 'Payment Required',
      403 => 'Forbidden',
      404 => 'Not Found',
      405 => 'Method Not Allowed',
      406 => 'Not Acceptable',
      407 => 'Proxy Authentication Required',
      408 => 'Request Timeout',
      409 => 'Conflict',
      410 => 'Gone',
      411 => 'Length Required',
      412 => 'Precondition Failed',
      413 => 'Payload Too Large',
      414 => 'URI Too Long',
      415 => 'Unsupported Media Type',
      416 => 'Range Not Satisfiable',
      417 => 'Expectation Failed',
      422 => 'Unprocessable Entity',
      423 => 'Locked',
      424 => 'Failed Dependency',
      426 => 'Upgrade Required',
      428 => 'Precondition Required',
      429 => 'Too Many Requests',
      431 => 'Request Header Fields Too Large',
      500 => 'Internal Server Error',
      501 => 'Not Implemented',
      502 => 'Bad Gateway',
      503 => 'Service Unavailable',
      504 => 'Gateway Timeout',
      505 => 'HTTP Version Not Supported',
      506 => 'Variant Also Negotiates',
      507 => 'Insufficient Storage',
      508 => 'Loop Detected',
      510 => 'Not Extended',
      511 => 'Network Authentication Required'
    }

    # Responses with HTTP status codes that should not have an entity body
    STATUS_WITH_NO_ENTITY_BODY = Set.new((100..199).to_a << 204 << 205 << 304)

    SYMBOL_TO_STATUS_CODE = Hash[*HTTP_STATUS_CODES.map { |code, message|
      [message.downcase.gsub(/\s|-|'/, '_').to_sym, code]
    }.flatten]

    def status_code(status)
      if status.is_a?(Symbol)
        SYMBOL_TO_STATUS_CODE[status] || 500
      else
        status.to_i
      end
    end
    module_function :status_code

    Multipart = Rack::Multipart

    PATH_SEPS = Regexp.union(*[::File::SEPARATOR, ::File::ALT_SEPARATOR].compact)

    def clean_path_info(path_info)
      parts = path_info.split PATH_SEPS

      clean = []

      parts.each do |part|
        next if part.empty? || part == '.'
        part == '..' ? clean.pop : clean << part
      end

      clean.unshift '/' if parts.empty? || parts.first.empty?

      ::File.join(*clean)
    end
    module_function :clean_path_info

  end
end

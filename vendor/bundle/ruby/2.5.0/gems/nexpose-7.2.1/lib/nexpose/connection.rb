module Nexpose
  # Object that represents a connection to a Nexpose Security Console.
  #
  # === Examples
  #   # Create a new Nexpose::Connection on the default port
  #   nsc = Connection.new('10.1.40.10', 'nxadmin', 'password')
  #
  #   # Create a new Nexpose::Connection from a URI or "URI" String
  #   nsc = Connection.from_uri('https://10.1.40.10:3780', 'nxadmin', 'password')
  #
  #   # Create a new Nexpose::Connection with a specific port
  #   nsc = Connection.new('10.1.40.10', 'nxadmin', 'password', 443)
  #
  #   # Create a new Nexpose::Connection with a silo identifier
  #   nsc = Connection.new('10.1.40.10', 'nxadmin', 'password', 3780, 'default')
  #
  #   # Create a new Nexpose::Connection with a two-factor authentication (2FA) token
  #   nsc = Connection.new('10.1.40.10', 'nxadmin', 'password', 3780, nil, '123456')
  #
  #   # Create a new Nexpose::Connection with an excplicitly trusted web certificate
  #   trusted_cert = ::File.read('cert.pem')
  #   nsc = Connection.new('10.1.40.10', 'nxadmin', 'password', 3780, nil, nil, trusted_cert)
  #
  #   # Login to NSC and Establish a Session ID
  #   nsc.login
  #
  #   # Check Session ID
  #   if nsc.session_id
  #       puts 'Login Successful'
  #   else
  #       puts 'Login Failure'
  #   end
  #
  #   # Logout
  #   logout_success = nsc.logout
  #
  class Connection
    include XMLUtils

    # Session ID of this connection
    attr_reader :session_id
    # The hostname or IP Address of the NSC
    attr_reader :host
    # The port of the NSC (default is 3780)
    attr_reader :port
    # The username used to login to the NSC
    attr_reader :username
    # The password used to login to the NSC
    attr_reader :password
    # The URL for communication
    attr_reader :url
    # The token used to login to the NSC
    attr_reader :token
    # The last XML request sent by this object, useful for debugging.
    attr_reader :request_xml
    # The last XML response received by this object, useful for debugging.
    attr_reader :response_xml
    # The trust store to validate connections against if any
    attr_reader :trust_store
    # The main HTTP read_timeout value, in seconds
    # For more information visit the link below:
    # https://ruby-doc.org/stdlib/libdoc/net/http/rdoc/Net/HTTP.html#read_timeout-attribute-method
    attr_accessor :timeout
    # The optional HTTP open_timeout value, in seconds
    # For more information visit the link below:
    # http://ruby-doc.org/stdlib/libdoc/net/http/rdoc/Net/HTTP.html#open_timeout-attribute-method
    attr_accessor :open_timeout

    # A constructor to load a Connection object from a URI
    def self.from_uri(uri, user, pass, silo_id = nil, token = nil, trust_cert = nil)
      uri = URI.parse(uri)
      new(uri.host, user, pass, uri.port, silo_id, token, trust_cert)
    end

    # A constructor for Connection
    #
    # @param [String] ip The IP address or hostname/FQDN of the Nexpose console.
    # @param [String] user The username for Nexpose sessions.
    # @param [String] pass The password for Nexpose sessions.
    # @param [Fixnum] port The port number of the Nexpose console.
    # @param [String] silo_id The silo identifier for Nexpose sessions.
    # @param [String] token The two-factor authentication (2FA) token for Nexpose sessions.
    # @param [String] trust_cert The PEM-formatted web certificate of the Nexpose console. Used for SSL validation.
    def initialize(ip, user, pass, port = 3780, silo_id = nil, token = nil, trust_cert = nil)
      @host         = ip
      @username     = user
      @password     = pass
      @port         = port
      @silo_id      = silo_id
      @token        = token
      @trust_store  = create_trust_store(trust_cert) unless trust_cert.nil?
      @session_id   = nil
      @url          = "https://#{@host}:#{@port}/api/API_VERSION/xml"
      @timeout      = 120
      @open_timeout = 120
    end

    # Establish a new connection and Session ID
    def login
      login_hash = { 'sync-id' => 0, 'password' => @password, 'user-id' => @username, 'token' => @token }
      login_hash['silo-id'] = @silo_id if @silo_id
      r = execute(make_xml('LoginRequest', login_hash))
      if r.success
        @session_id = r.sid
        true
      end
    rescue APIError
      raise AuthenticationFailed.new(r)
    end

    # Logout of the current connection
    def logout
      r = execute(make_xml('LogoutRequest', { 'sync-id' => 0 }))
      return true if r.success
      raise APIError.new(r, 'Logout failed')
    end

    # Execute an API request
    def execute(xml, version = '1.1', options = {})
      options.store(:timeout, @timeout) unless options.key?(:timeout)
      options.store(:open_timeout, @open_timeout)
      @request_xml = xml.to_s
      @api_version = version
      response = APIRequest.execute(@url, @request_xml, @api_version, options, @trust_store)
      @response_xml = response.raw_response_data
      response
    end

    # Download a specific URL, typically a report.
    # Include an optional file_name parameter to write the output to a file.
    #
    # Note: XML and HTML reports have charts not downloaded by this method.
    #       Would need to do something more sophisticated to grab
    #       all the associated image files.
    def download(url, file_name = nil)
      return nil if (url.nil? || url.empty?)
      uri          = URI.parse(url)
      http         = Net::HTTP.new(@host, @port)
      http.use_ssl = true
      if @trust_store.nil?
        http.verify_mode = OpenSSL::SSL::VERIFY_NONE # XXX: security issue
      else
        http.cert_store = @trust_store
      end
      headers = { 'Cookie' => "nexposeCCSessionID=#{@session_id}" }

      if file_name
        http.request_get(uri.to_s, headers) do |resp|
          ::File.open(file_name, 'wb') do |file|
            resp.read_body { |chunk| file.write(chunk) }
          end
        end
      else
        resp = http.get(uri.to_s, headers)
        resp.body
      end
    end

    def create_trust_store(trust_cert)
      store = OpenSSL::X509::Store.new
      store.trust
      store.add_cert(OpenSSL::X509::Certificate.new(trust_cert))
      store
    end

    private :create_trust_store
  end
end

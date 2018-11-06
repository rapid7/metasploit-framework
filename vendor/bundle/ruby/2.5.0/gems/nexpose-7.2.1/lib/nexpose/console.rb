# here uh what
module Nexpose

  # Nexpose console configuration class.
  #
  # Changes to this object are not persisted until the #save method is called.
  #
  # Example usage:
  #   config = Nexpose::Console.load(nsc)
  #   config.session_timeout = 600
  #   config.save(nsc)
  #
  class Console

    # Session timeout for the Nexpose web server (in seconds).
    # The web interface enforces a value from 60 to 604,800 [1 minute to 7 days].
    attr_accessor :session_timeout

    # Impose a limit on the number of scan threads which an individual scan can use.
    attr_accessor :scan_threads_limit

    # Whether to retrieve incremental scan results from distributed engines.
    attr_accessor :incremental_scan_results

    # XML document representing the entire configuration.
    attr_accessor :xml

    # Construct a new Nexpose Security Console configuration object.
    # Not meant to be called publicly.
    # @see #load
    #
    # @param [REXML::Document] xml Parsed XML representation of the configuration.
    #
    def initialize(xml)
      @xml = xml
      nsc                       = REXML::XPath.first(@xml, 'NeXposeSecurityConsole')
      @scan_threads_limit       = nsc.attributes['scanThreadsLimit'].to_i
      @incremental_scan_results = nsc.attributes['realtimeIntegration'] == '1'

      web_server                = REXML::XPath.first(nsc, 'WebServer')
      @session_timeout          = web_server.attributes['sessionTimeout'].to_i
    end

    # Load existing Nexpose security console configuration.
    #
    # @param [Connection] connection Nexpose connection.
    #
    def self.load(connection)
      xml = REXML::Document.new(Nexpose::AJAX.get(connection, '/data/admin/config/nsc'))
      new(xml)
    end

    # Save modifications to the Nexpose security console.
    #
    # @param [Connection] connection Nexpose connection.
    # @return [Boolean] true if configuration successfully saved.
    #
    def save(connection)
      nsc                                   = REXML::XPath.first(@xml, 'NeXposeSecurityConsole')
      nsc.attributes['scanThreadsLimit']    = @scan_threads_limit.to_i
      nsc.attributes['realtimeIntegration'] = @incremental_scan_results ? '1' : '0'

      web_server                              = REXML::XPath.first(nsc, 'WebServer')
      web_server.attributes['sessionTimeout'] = @session_timeout.to_i

      response = REXML::Document.new(Nexpose::AJAX.post(connection, '/data/admin/config/nsc', @xml))
      saved    = REXML::XPath.first(response, 'SaveConfig')
      saved.attributes['success'] == '1'
    end
  end
end

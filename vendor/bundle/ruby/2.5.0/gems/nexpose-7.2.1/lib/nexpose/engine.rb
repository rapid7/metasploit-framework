module Nexpose

  class Connection
    include XMLUtils

    # Removes a scan engine from the list of available engines.
    #
    # @param [Fixnum] engine_id Unique ID of an existing engine to remove.
    # @param [String] scope Whether the engine is global or silo scoped.
    # @return [Boolean] true if engine successfully deleted.
    #
    def delete_engine(engine_id, scope = 'silo')
      xml = make_xml('EngineDeleteRequest', { 'engine-id' => engine_id, 'scope' => scope })
      response = execute(xml, '1.2')
      response.success
    end

    # Reverses the direction of a connection to an engine
    # If the connection is currently initiated from the console this method
    # will have the engine initiate the connection. If the connection is
    # currently initiated by the engine this method with initiate the connection
    # from the console instead. Requires a restart of the console for the
    # connection to be properly established.
    #
    # @param [Fixnum] engine_id Unique ID of the engine.
    # @return [Boolean] true if the connection is successfully reversed.
    #
    def reverse_engine_connection(engine_id)
      uri      = "/api/2.1/engine/#{engine_id}/reverseConnection"
      response = AJAX.put(self, uri)
      response.eql?('true')
    end

    # Kicks off an update on a single engine.
    # A return result of true should be taken only to mean that the update
    # was sent, not that it correctly applied.
    #
    # Nexpose::APIError will be raised if the engine is already updating,
    # or if the engine is offline or unresponsive.
    #
    # @param [Fixnum] engine_id Unique ID of the engine.
    # @return [Boolean] true if the update was sent
    #   or if engine is already up to date.
    #
    def update_engine(engine_id)
      uri = "/data/engine/#{engine_id}/update"
      AJAX.post(self, uri)
    end

    # Provide a list of current scan activities for a specific Scan Engine.
    #
    # @return [Array[ScanSummary]] Array of ScanSummary objects associated with
    #   each active scan on the engine.
    #
    def engine_activity(engine_id)
      xml = make_xml('EngineActivityRequest', { 'engine-id' => engine_id })
      r   = execute(xml)
      arr = []
      if r.success
        r.res.elements.each('//ScanSummary') do |scan_event|
          arr << ScanSummary.parse(scan_event)
        end
      end
      arr
    end

    # Retrieve a list of all Scan Engines managed by the Security Console.
    #
    # @return [Array[EngineSummary]] Array of EngineSummary objects associated
    #   with each engine associated with this security console.
    #
    def list_engines
      response = execute(make_xml('EngineListingRequest'))
      arr      = []
      if response.success
        response.res.elements.each('//EngineSummary') do |engine|
          arr << EngineSummary.new(engine.attributes['id'].to_i,
                                   engine.attributes['name'],
                                   engine.attributes['address'],
                                   engine.attributes['port'].to_i,
                                   engine.attributes['status'],
                                   engine.attributes['scope'])
        end
      end
      arr
    end

    alias engines list_engines
  end

  # Object representing the current details of a scan engine attached to the
  # security console.
  #
  class EngineSummary

    # A unique ID that identifies this scan engine.
    attr_reader :id
    # The name of this scan engine.
    attr_reader :name
    # The hostname or IP address of the engine.
    attr_reader :address
    # The port there the engine is listening.
    attr_reader :port
    # The engine status. One of: active, pending-auth, incompatible,
    # not-responding, unknown
    attr_reader :status
    # A parameter that specifies whether the engine has a global
    # or silo-specific scope.
    attr_reader :scope

    def initialize(id, name, address, port, status, scope = 'silo')
      @id      = id
      @name    = name
      @address = address
      @port    = port
      @status  = status
      @scope   = scope
    end
  end

  # Engine connnection to a Nexpose console.
  #
  class Engine

    # Unique numeric identifier for the scan engine, assigned by the console
    # in the order of creation.
    attr_accessor :id
    # The IP address or DNS name of a scan engine.
    attr_accessor :address
    # A name assigned to the scan engine by the security console.
    attr_accessor :name
    # The port on which the engine listens for requests from the security
    # console.
    attr_accessor :port
    # Whether the engine has a global or silo-specific scope.
    attr_accessor :scope
    # Relative priority of a scan engine.
    # One of: very-low, low, normal, high, very-high
    attr_accessor :priority

    # Sites to which the scan engine is assigned.
    attr_accessor :sites

    def initialize(address, name = nil, port = 40814)
      @id      = -1
      @address = address
      @name    = name
      @name  ||= address
      @port    = port
      @scope   = 'silo'
      @sites   = []
    end

    def self.load(connection, id)
      xml = '<EngineConfigRequest session-id="' + connection.session_id + '"'
      xml << %( engine-id="#{id}")
      xml << ' />'
      r = connection.execute(xml, '1.2')

      if r.success
        r.res.elements.each('EngineConfigResponse/EngineConfig') do |config|
          engine = Engine.new(config.attributes['address'],
                              config.attributes['name'],
                              config.attributes['port'])
          engine.id       = config.attributes['id']
          engine.scope    = config.attributes['scope'] if config.attributes['scope']
          engine.priority = config.attributes['priority'] if config.attributes['priority']

          config.elements.each('Site') do |site|
            engine.sites << SiteSummary.new(site.attributes['id'], site.attributes['name'])
          end

          return engine
        end
      end
      nil
    end

    # Assign a site to this scan engine.
    #
    # @param [Fixnum] site_id Unique numerical ID of the site.
    #
    def add_site(site_id)
      sites << SiteSummary.new(site_id, nil)
    end

    include Sanitize

    def to_xml
      xml = '<EngineConfig'
      xml << %( id="#{id}")
      xml << %( address="#{address}")
      xml << %( name="#{replace_entities(name)}")
      xml << %( port="#{port}")
      xml << %( scope="#{scope}") if scope
      xml << %( priority="#{priority}") if priority
      xml << '>'
      sites.each do |site|
        xml << %(<Site id="#{site.id}" />)
      end
      xml << '</EngineConfig>'
      xml
    end

    # Save this engine configuration to the security console.
    #
    # @param [Connection] connection Connection to console where site exists.
    # @return [Fixnum] ID assigned to the scan engine.
    #
    def save(connection)
      xml = '<EngineSaveRequest session-id="' + connection.session_id + '">'
      xml << to_xml
      xml << '</EngineSaveRequest>'

      r = connection.execute(xml, '1.2')
      if r.success
        r.res.elements.each('EngineSaveResponse/EngineConfig') do |v|
          return @id = v.attributes['id'].to_i
        end
      end
    end

    # Delete this scan engine configuration from the security console.
    #
    # @param [Connection] connection Connection to console where site exists.
    #
    def delete(connection)
      connection.delete_engine(@id, @scope)
    end
  end
end

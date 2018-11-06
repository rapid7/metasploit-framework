module Nexpose

  class Connection
    include XMLUtils

    # Retrieve a list of all Scan Engine Pools managed by the Security Console.
    #
    # @return [Array[EnginePoolSummary]] Array of EnginePoolSummary objects
    #   associated with each engine associated with this security console.
    #
    def list_engine_pools
      response = execute(make_xml('EnginePoolListingRequest'), '1.2')
      arr = []
      if response.success
        response.res.elements.each('EnginePoolListingResponse/EnginePoolSummary') do |pool|
          arr << EnginePoolSummary.new(pool.attributes['id'],
                                       pool.attributes['name'],
                                       pool.attributes['scope'])
        end
      end
      arr
    end

    alias engine_pools list_engine_pools
  end

  # A summary of an engine pool.
  #
  class EnginePoolSummary

    # Unique identifier of the engine pool.
    attr_reader :id
    # Name of the engine pool.
    attr_reader :name
    # Whether the engine pool has global or silo scope.
    attr_reader :scope

    def initialize(id, name, scope = 'silo')
      @id    = id.to_i
      @name  = name
      @scope = scope
    end

    # Deletes an engine pool
    #
    # @param [Connection] conn Connection to console where site exists.
    #
    def delete(conn)
      xml = conn.make_xml('EnginePoolDeleteRequest')
      xml.add_element(as_xml)
      result = conn.execute(xml, '1.2')
      result.success
    end

    def as_xml
      xml = REXML::Element.new('EnginePool')
      xml.add_attribute('name', @name)
      xml.add_attribute('scope', @scope)
      xml
    end
  end

  # Engine pool configuration object.
  #
  class EnginePool

    # Unique identifier of the engine pool.
    attr_accessor :id
    # Name of the engine pool.
    attr_accessor :name
    # Whether the engine pool has global or silo scope.
    attr_accessor :scope
    # Array containing (EngineSummary*) for each engine assigned to the pool.
    attr_accessor :engines

    def initialize(name, scope = 'silo', id = -1)
      @name    = name
      @scope   = scope
      @id      = id.to_i
      @engines = []
    end

    # Add an engine to the pool by name (not ID).
    #
    # EngineSummary objects should just be appended to the pool directly,
    #   e.g., pool.engines << nsc.engines.find { |e| e.name == 'Cleveland' }
    #
    # @param [String] engine_name Name used to identify a paired scan engine.
    #
    def add(engine_name)
      @engines << EngineSummary.new(-1, engine_name, nil, 40814, nil)
    end

    # Returns detailed information about a single engine pool.
    #
    # @param [Connection] connection Connection to console where site exists.
    # @param [String] name The name of the engine pool.
    # @param [String] scope The silo of the engine pool.
    # @return [EnginePool] Engine pool configuration object.
    #
    def self.load(connection, name, scope = 'silo')
      xml = %(<EnginePoolDetailsRequest session-id="#{connection.session_id}">)
      xml << %(<EnginePool name="#{name}" scope="#{scope}"/>)
      xml << '</EnginePoolDetailsRequest>'
      r = connection.execute(xml, '1.2')
      if r.success
        r.res.elements.each('EnginePoolDetailsResponse/EnginePool') do |pool|
          config = EnginePool.new(pool.attributes['name'],
                                  pool.attributes['scope'],
                                  pool.attributes['id'].to_i)
          r.res.elements.each('EnginePoolDetailsResponse/EnginePool/EngineSummary') do |summary|
            config.engines << EngineSummary.new(summary.attributes['id'].to_i,
                                                summary.attributes['name'],
                                                summary.attributes['address'],
                                                summary.attributes['port'].to_i,
                                                summary.attributes['status'],
                                                summary.attributes['scope'])
          end
          return config
        end
      end
      nil
    end

    # Save an engine pool to a security console.
    #
    # @param [Connection] connection Connection to console where site exists.
    #
    def save(connection)
      request = @id > 0 ? 'EnginePoolUpdateRequest' : 'EnginePoolCreateRequest'
      xml = %(<#{request} session-id="#{connection.session_id}">)
      xml << '<EnginePool'
      xml << %( id="#{@id}") if @id > 0
      xml << %( name="#{@name}" scope="#{@scope}">)
      @engines.each do |engine|
        xml << %(<Engine name="#{engine.name}" />)
      end
      xml << '</EnginePool>'
      xml << %(</#{request}>)

      r = connection.execute(xml, '1.2')
      if r.success
        r.res.elements.each(request.gsub('Request', 'Response')) do |v|
          return @id = v.attributes['id'].to_i
        end
      end
    end

    # Deletes an engine pool
    #
    # @param [Connection] connection Connection to console where site exists.
    #
    def delete(connection)
      xml = %(<EnginePoolDeleteRequest session-id="#{connection.session_id}">)
      xml << %(<EnginePool name="#{@name}" scope="#{@scope}" />)
      xml << '</EnginePoolDeleteRequest>'

      r = connection.execute(xml, '1.2')
      r.success
    end
  end
end

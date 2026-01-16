require 'neo4j/driver'

module HypergraphNeo4j
  class Graph
    # Allowed property names for artisanal modifications
    ALLOWED_PROPERTIES = %w[
      authentication_in
      authentication_out
      platform
      session_type_in
      session_type_out
    ].freeze

    def initialize(uri: 'neo4j://localhost:7687', user: 'neo4j', password: 'neo4j')
      @driver = Neo4j::Driver::GraphDatabase.driver(uri, Neo4j::Driver::AuthTokens.basic(user, password))
      puts "Connected to Neo4j"
    end

    def close
      @driver.close
      puts "Connection closed"
    end

    def clear_database
      session do |session|
        session.run('MATCH (n) DETACH DELETE n')
      end
      puts "Database cleared"
    end

    def create_node(node_id, properties = {})
      # Convert all property keys to strings and ensure values are Neo4j-compatible
      neo4j_props = properties.transform_keys(&:to_s).transform_values do |value|
        case value
        when Symbol
          value.to_s
        when Array
          value.map { |v| v.is_a?(Symbol) ? v.to_s : v }
        else
          value
        end
      end

      # Build property string for Cypher query to avoid driver serialization issues
      props_str = neo4j_props.map do |key, value|
        cypher_value = case value
        when nil
          "NULL"
        when Array
          "[" + value.map { |v| escape_cypher_string(v.to_s) }.join(", ") + "]"
        when String
          escape_cypher_string(value)
        else
          escape_cypher_string(value.to_s)
        end
        "#{key}: #{cypher_value}"
      end.join(", ")

      session do |session|
        # Use inline values instead of parameters to avoid Ruby 3.x driver issues
        session.run(
          "MERGE (n:Node {id: #{escape_cypher_string(node_id.to_s)}}) SET n += {#{props_str}}"
        )
      end
      #puts "Created node: #{node_id}"
    end

    def create_hyperedge(hyperedge_id, node_ids, hyperedge_properties = {})
      session do |session|
        # Create the hyperedge node
        session.run(
          'MERGE (h:Hyperedge {id: $hyperedge_id}) SET h += $props',
          hyperedge_id: hyperedge_id,
          props: hyperedge_properties
        )

        # Connect all nodes to this hyperedge
        node_ids.each do |node_id|
          session.run(
            'MATCH (h:Hyperedge {id: $hyperedge_id}) ' \
            'MERGE (n:Node {id: $node_id}) ' \
            'MERGE (n)-[:PARTICIPATES_IN]->(h)',
            hyperedge_id: hyperedge_id,
            node_id: node_id
          )
        end
      end
      puts "Created hyperedge: #{hyperedge_id} connecting #{node_ids.length} nodes"
    end

    def create_subgraph(subgraph_id, properties = {})
      session do |session|
        session.run(
          'MERGE (sg:Subgraph {id: $subgraph_id}) SET sg += $props',
          subgraph_id: subgraph_id,
          props: properties
        )
      end
      puts "Created subgraph: #{subgraph_id}"
    end

    def create_node_in_subgraph(node_id, subgraph_id, properties = {})
      session do |session|
        session.run(
          'MATCH (sg:Subgraph {id: $subgraph_id}) ' \
          'MERGE (n:Node {id: $node_id}) ' \
          'SET n += $props ' \
          'MERGE (n)-[:BELONGS_TO]->(sg)',
          node_id: node_id,
          subgraph_id: subgraph_id,
          props: properties
        )
      end
      puts "Created node #{node_id} in subgraph #{subgraph_id}"
    end

    def create_hyperedge_in_subgraph(hyperedge_id, node_ids, subgraph_id, hyperedge_properties = {})
      session do |session|
        # Create hyperedge and link to subgraph
        session.run(
          'MATCH (sg:Subgraph {id: $subgraph_id}) ' \
          'MERGE (h:Hyperedge {id: $hyperedge_id}) ' \
          'SET h += $props ' \
          'MERGE (h)-[:BELONGS_TO]->(sg)',
          hyperedge_id: hyperedge_id,
          subgraph_id: subgraph_id,
          props: hyperedge_properties
        )

        # Connect nodes to hyperedge
        node_ids.each do |node_id|
          session.run(
            'MATCH (h:Hyperedge {id: $hyperedge_id}) ' \
            'MATCH (n:Node {id: $node_id}) ' \
            'MERGE (n)-[:PARTICIPATES_IN]->(h)',
            hyperedge_id: hyperedge_id,
            node_id: node_id
          )
        end
      end
      puts "Created hyperedge #{hyperedge_id} in subgraph #{subgraph_id}"
    end

    def get_hyperedge_nodes(hyperedge_id)
      results = []
      session do |session|
        result = session.run(
          'MATCH (n:Node)-[:PARTICIPATES_IN]->(h:Hyperedge {id: $hyperedge_id}) ' \
          'RETURN n.id as node_id, n',
          hyperedge_id: hyperedge_id
        )
        result.each do |record|
          results << {
            id: record['node_id'],
            properties: record['n'].properties
          }
        end
      end
      results
    end

    def get_node_hyperedges(node_id)
      results = []
      session do |session|
        result = session.run(
          'MATCH (n:Node {id: $node_id})-[:PARTICIPATES_IN]->(h:Hyperedge) ' \
          'RETURN h.id as hyperedge_id, h',
          node_id: node_id
        )
        result.each do |record|
          results << {
            id: record['hyperedge_id'],
            properties: record['h'].properties
          }
        end
      end
      results
    end

    def update_node_properties(node_id, additions: {}, removals: {})
      # Validate that the node exists
      node_exists = false
      session do |session|
        result = session.run(
          "MATCH (n:Node {id: #{escape_cypher_string(node_id.to_s)}}) RETURN count(n) as count"
        )
        node_exists = result.first['count'] > 0
      end

      unless node_exists
        raise ArgumentError, "Module '#{node_id}' does not exist in the database. Check for typos in the module name."
      end

      # Validate property names against allowed properties
      all_properties = (additions.keys + removals.keys).map(&:to_s)
      invalid_properties = all_properties - ALLOWED_PROPERTIES
      unless invalid_properties.empty?
        raise ArgumentError, "Invalid property names for module '#{node_id}': #{invalid_properties.join(', ')}. Allowed properties: #{ALLOWED_PROPERTIES.join(', ')}"
      end

      # Add new properties or append to existing array properties
      unless additions.empty?
        additions_str = additions.map do |key, value|
          cypher_value = case value
          when Array
            "[" + value.map { |v| escape_cypher_string(v.to_s) }.join(", ") + "]"
          when String
            escape_cypher_string(value)
          else
            escape_cypher_string(value.to_s)
          end
          "#{key}: #{cypher_value}"
        end.join(", ")

        session do |session|
          session.run(
            "MATCH (n:Node {id: #{escape_cypher_string(node_id.to_s)}}) SET n += {#{additions_str}}"
          )
        end
      end

      # Remove specific values from array properties
      unless removals.empty?
        removals.each do |property, values_to_remove|
          values_to_remove = [values_to_remove] unless values_to_remove.is_a?(Array)

          # Build array of escaped values to remove
          escaped_values = values_to_remove.map { |v| escape_cypher_string(v.to_s) }.join(", ")

          session do |session|
            session.run(<<~CYPHER)
              MATCH (n:Node {id: #{escape_cypher_string(node_id.to_s)}})
              WHERE n.#{property} IS NOT NULL
              SET n.#{property} = [x IN n.#{property} WHERE NOT x IN [#{escaped_values}]]
            CYPHER
          end
        end
      end
    end

    def get_hypergraph_stats
      stats = {}
      session do |session|
        result = session.run(
          'MATCH (n:Node) ' \
          'OPTIONAL MATCH (n)-[:PARTICIPATES_IN]->(h:Hyperedge) ' \
          'WITH count(DISTINCT n) as node_count, count(DISTINCT h) as hyperedge_count ' \
          'MATCH (h:Hyperedge)<-[r:PARTICIPATES_IN]-(n:Node) ' \
          'WITH node_count, hyperedge_count, h, count(r) as edge_size ' \
          'RETURN node_count, hyperedge_count, ' \
          'avg(edge_size) as avg_hyperedge_size, ' \
          'max(edge_size) as max_hyperedge_size, ' \
          'min(edge_size) as min_hyperedge_size'
        )
        record = result.first
        if record
          stats = {
            nodes: record['node_count'],
            hyperedges: record['hyperedge_count'],
            avg_hyperedge_size: record['avg_hyperedge_size'],
            max_hyperedge_size: record['max_hyperedge_size'],
            min_hyperedge_size: record['min_hyperedge_size']
          }
        end
      end
      stats
    end

    private

    def escape_cypher_string(str)
      # Escape single quotes and backslashes for Cypher string literals
      escaped = str.to_s.gsub('\\', '\\\\\\\\').gsub("'", "\\\\'")
      "'#{escaped}'"
    end

    def session(&block)
      @driver.session do |session|
        block.call(session)
      end
    end
  end
end
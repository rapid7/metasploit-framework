require 'neo4j/driver'

module Msf
  module Neo4j
    class Graph
    # Allowed property names for artisanal modifications
    ALLOWED_PROPERTIES = %w[
      authentication_in
      authentication_out
      platform
      session_in
      session_out
      trigger_in
      trigger_out
    ].freeze

    # Requirement types for the intermediate node model
    # These map requirement values to their typed node labels
    REQUIREMENT_TYPES = {
      # Session types - represent shell/protocol sessions (platform-qualified)
      # Session IDs are formatted as: session/{platform}/{session_type}
      # e.g., session/windows/meterpreter, session/linux/shell
      session: {
        label: 'Session',
        base_values: %w[shell meterpreter powershell cmd]
      },
      # Authentication types - credentials and auth mechanisms
      authentication: {
        label: 'Authentication',
        values: %w[plaintext hash/net-ntlm hash/ntlm kerberos kerberos/keys certificate session/ldap session/mssql session/mysql session/postgresql session/smb]
      },
      # Information types - gathered data that enables further attacks
      # information: {
      #   label: 'Information',
      #   values: %w[domain_sid computer_account machine_key]
      # },
      # Trigger types - events/conditions that enable subsequent modules
      # Used for coercion mechanisms (active like PetitPotam, passive like NBNS)
      # that provide inbound authentication to capture/relay modules
      # - 'coercion' = generic coercion (any mechanism, e.g., NBNS/LLMNR poisoning)
      # - 'coercion/smb' = SMB-specific coercion (e.g., PetitPotam, PrinterBug)
      # Capture modules may accept either generic OR protocol-specific coercion
      trigger: {
        label: 'Trigger',
        values: %w[coercion coercion/smb coercion/http coercion/ldap coercion/webdav]
      }
    }.freeze

    # Base session types (without platform qualification)
    SESSION_TYPES = %w[shell meterpreter powershell cmd].freeze

    # Default batch size for relationship building
    DEFAULT_BATCH_SIZE = 500

    def initialize(uri: 'neo4j://localhost:7687', user: 'neo4j', password: 'neo4j')
      @driver = ::Neo4j::Driver::GraphDatabase.driver(uri, ::Neo4j::Driver::AuthTokens.basic(user, password))
      puts "Connected to Neo4j"
    end

    def close
      @driver.close
      puts "Connection closed"
    end

    def clear_database(batch_size: DEFAULT_BATCH_SIZE)
      # Delete in batches to avoid transaction memory limits
      loop do
        deleted = 0
        session do |sess|
          result = sess.run(<<~CYPHER)
            MATCH (n)
            WITH n LIMIT #{batch_size}
            DETACH DELETE n
            RETURN count(*) AS deleted
          CYPHER
          deleted = result.first&.[]('deleted') || 0
        end
        break if deleted == 0
      end
      puts "Database cleared"
    end

    def create_module(module_id, properties = {})
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
          "MERGE (n:Module {id: #{escape_cypher_string(module_id.to_s)}}) SET n += {#{props_str}}"
        )
      end
      #puts "Created module: #{module_id}"
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
            'MERGE (n:Module {id: $node_id}) ' \
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

    def create_module_in_subgraph(module_id, subgraph_id, properties = {})
      session do |session|
        session.run(
          'MATCH (sg:Subgraph {id: $subgraph_id}) ' \
          'MERGE (n:Module {id: $module_id}) ' \
          'SET n += $props ' \
          'MERGE (n)-[:BELONGS_TO]->(sg)',
          module_id: module_id,
          subgraph_id: subgraph_id,
          props: properties
        )
      end
      puts "Created module #{module_id} in subgraph #{subgraph_id}"
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
            'MATCH (n:Module {id: $node_id}) ' \
            'MERGE (n)-[:PARTICIPATES_IN]->(h)',
            hyperedge_id: hyperedge_id,
            node_id: node_id
          )
        end
      end
      puts "Created hyperedge #{hyperedge_id} in subgraph #{subgraph_id}"
    end

    def get_hyperedge_modules(hyperedge_id)
      results = []
      session do |session|
        result = session.run(
          'MATCH (n:Module)-[:PARTICIPATES_IN]->(h:Hyperedge {id: $hyperedge_id}) ' \
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

    def get_module_hyperedges(module_id)
      results = []
      session do |session|
        result = session.run(
          'MATCH (n:Module {id: $module_id})-[:PARTICIPATES_IN]->(h:Hyperedge) ' \
          'RETURN h.id as hyperedge_id, h',
          module_id: module_id
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

    def update_module_properties(module_id, additions: {}, removals: {})
      # Validate that the module exists
      module_exists = false
      session do |session|
        result = session.run(
          "MATCH (n:Module {id: #{escape_cypher_string(module_id.to_s)}}) RETURN count(n) as count"
        )
        module_exists = result.first['count'] > 0
      end

      unless module_exists
        raise ArgumentError, "Module '#{module_id}' does not exist in the database. Check for typos in the module name."
      end

      # Validate property names against allowed properties
      all_properties = (additions.keys + removals.keys).map(&:to_s)
      invalid_properties = all_properties - ALLOWED_PROPERTIES
      unless invalid_properties.empty?
        raise ArgumentError, "Invalid property names for module '#{module_id}': #{invalid_properties.join(', ')}. Allowed properties: #{ALLOWED_PROPERTIES.join(', ')}"
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
            "MATCH (n:Module {id: #{escape_cypher_string(module_id.to_s)}}) SET n += {#{additions_str}}"
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
              MATCH (n:Module {id: #{escape_cypher_string(module_id.to_s)}})
              WHERE n.#{property} IS NOT NULL
              SET n.#{property} = [x IN n.#{property} WHERE NOT x IN [#{escaped_values}]]
            CYPHER
          end
        end
      end
    end

    def create_authentication_relationships
      # Create relationships between modules where one's auth output enables another's auth input
      session do |session|
        session.run(<<~CYPHER)
          MATCH (provider:Module), (consumer:Module)
          WHERE provider.authentication_out IS NOT NULL
            AND consumer.authentication_in IS NOT NULL
            AND any(auth_out IN provider.authentication_out
                WHERE auth_out IN consumer.authentication_in)
          WITH provider, consumer,
               [auth IN provider.authentication_out WHERE auth IN consumer.authentication_in] as shared_auth
          MERGE (provider)-[r:PROVIDES_AUTHENTICATION]->(consumer)
          SET r.auth_types = shared_auth
        CYPHER
      end
      puts "Created authentication flow relationships"
    end

    def create_session_relationships
      # Create relationships between modules where one creates sessions that another can use
      session do |session|
        session.run(<<~CYPHER)
          MATCH (provider:Module), (consumer:Module)
          WHERE provider.session_out IS NOT NULL
            AND consumer.session_in IS NOT NULL
            AND any(session_out IN provider.session_out
                WHERE session_out IN consumer.session_in)
          WITH provider, consumer,
               [session_type IN provider.session_out WHERE session_type IN consumer.session_in] as shared_sessions
          MERGE (provider)-[r:PROVIDES_SESSION_TYPE]->(consumer)
          SET r.session_types = shared_sessions
        CYPHER
      end
      puts "Created session flow relationships"
    end

    def create_all_relationships
      create_authentication_relationships
      create_session_relationships
    end

    # =========================================================================
    # REQUIREMENT NODE MODEL
    # =========================================================================
    # The requirement node model creates intermediate typed nodes (Session,
    # Authentication, Information, Trigger) that modules connect to via PRODUCES
    # and REQUIRES relationships. This enables:
    # - More efficient pathfinding (no cartesian products)
    # - Multi-requirement satisfaction queries
    # - Better graph visualization
    # =========================================================================

    # Create a typed requirement node
    def create_requirement_node(value, label:)
      raise ArgumentError unless REQUIREMENT_TYPES.values.any? { |requirement| requirement[:label] == label }

      session do |session|
        session.run(
          "MERGE (r:Requirement:#{label} {id: #{escape_cypher_string(value)}})"
        )
      end
    end

    # Create all requirement nodes from module properties in batches
    # Session requirements are platform-qualified: session/{platform}/{session_type}
    def create_requirement_nodes(batch_size: DEFAULT_BATCH_SIZE)
      puts "Creating requirement nodes..."

      # Collect authentication requirement values (not platform-qualified)
      authentication_values = Set.new

      # Collect platform-qualified session requirement values
      session_values = Set.new

      # Collect trigger requirement values
      trigger_values = Set.new

      session do |session|
        # Get all authentication_out values
        result = session.run(<<~CYPHER)
          MATCH (m:Module)
          WHERE m.authentication_out IS NOT NULL
          UNWIND m.authentication_out AS auth
          RETURN DISTINCT auth AS value
        CYPHER
        result.each { |record| authentication_values.add(record['value']) }

        # Get all authentication_in values
        result = session.run(<<~CYPHER)
          MATCH (m:Module)
          WHERE m.authentication_in IS NOT NULL
          UNWIND m.authentication_in AS auth
          RETURN DISTINCT auth AS value
        CYPHER
        result.each { |record| authentication_values.add(record['value']) }

        # Get session_out values (already platform-qualified as {platform}/{session_type})
        # Prepend 'session/' to create final ID: session/{platform}/{session_type}
        result = session.run(<<~CYPHER)
          MATCH (m:Module)
          WHERE m.session_out IS NOT NULL
          UNWIND m.session_out AS sess_value
          RETURN DISTINCT sess_value AS value
        CYPHER
        result.each { |record| session_values.add(record['value']) }

        # Get session_in values (already platform-qualified as {platform}/{session_type})
        result = session.run(<<~CYPHER)
          MATCH (m:Module)
          WHERE m.session_in IS NOT NULL
          UNWIND m.session_in AS sess_value
          RETURN DISTINCT sess_value AS value
        CYPHER
        result.each { |record| session_values.add(record['value']) }

        # Get all trigger_out values
        result = session.run(<<~CYPHER)
          MATCH (m:Module)
          WHERE m.trigger_out IS NOT NULL
          UNWIND m.trigger_out AS trig
          RETURN DISTINCT trig AS value
        CYPHER
        result.each { |record| trigger_values.add(record['value']) }

        # Get all trigger_in values
        result = session.run(<<~CYPHER)
          MATCH (m:Module)
          WHERE m.trigger_in IS NOT NULL
          UNWIND m.trigger_in AS trig
          RETURN DISTINCT trig AS value
        CYPHER
        result.each { |record| trigger_values.add(record['value']) }
      end

      puts "  Found #{authentication_values.size} authentication requirement values"
      puts "  Found #{session_values.size} platform-qualified session requirement values"
      puts "  Found #{trigger_values.size} trigger requirement values"

      # Create authentication requirement nodes in batches
      authentication_values.each_slice(batch_size) do |batch|
        session do |session|
          batch.each do |value|
            session.run(
              "MERGE (r:Requirement:Authentication {id: #{escape_cypher_string(value)}})"
            )
          end
        end
      end

      # Create session requirement nodes in batches
      session_values.each_slice(batch_size) do |batch|
        session do |session|
          batch.each do |value|
            session.run(
              "MERGE (r:Requirement:Authentication {id: #{escape_cypher_string("session/#{value}")}})"
            )
            session.run(
              "MERGE (r:Requirement:Session {id: #{escape_cypher_string(value)}})"
            )
          end
        end
      end

      # Create trigger requirement nodes in batches
      trigger_values.each_slice(batch_size) do |batch|
        session do |session|
          batch.each do |value|
            session.run(
              "MERGE (r:Requirement:Trigger {id: #{escape_cypher_string(value)}})"
            )
          end
        end
      end

      puts "  Created requirement nodes"
    end

    # Create PRODUCES relationships from modules to requirement nodes (batched)
    # Session relationships use platform-qualified IDs: session/{platform}/{session_type}
    def create_produces_relationships(batch_size: DEFAULT_BATCH_SIZE)
      puts "Creating PRODUCES relationships..."

      # Session PRODUCES relationships (session_out values are already {platform}/{session_type})
      session do |session|
        session.run(<<~CYPHER)
          CALL {
            MATCH (m:Module)
            WHERE m.session_out IS NOT NULL
            UNWIND m.session_out AS sess_value
            WITH m, 'session/' + sess_value AS qualified_id
            MATCH (r:Requirement {id: qualified_id})
            MERGE (m)-[:PRODUCES {type: 'session'}]->(r)
          } IN TRANSACTIONS OF #{batch_size} ROWS
        CYPHER
      end
      puts "  Created session PRODUCES relationships"

      # Authentication PRODUCES relationships (authentication_out -> Authentication nodes)
      session do |session|
        session.run(<<~CYPHER)
          CALL {
            MATCH (m:Module)
            WHERE m.authentication_out IS NOT NULL
            UNWIND m.authentication_out AS auth_type
            MATCH (r:Requirement {id: auth_type})
            MERGE (m)-[:PRODUCES {type: 'authentication'}]->(r)
          } IN TRANSACTIONS OF #{batch_size} ROWS
        CYPHER
      end
      puts "  Created authentication PRODUCES relationships"

      # Trigger PRODUCES relationships (trigger_out -> Trigger nodes)
      session do |session|
        session.run(<<~CYPHER)
          CALL {
            MATCH (m:Module)
            WHERE m.trigger_out IS NOT NULL
            UNWIND m.trigger_out AS trigger_type
            MATCH (r:Requirement {id: trigger_type})
            MERGE (m)-[:PRODUCES {type: 'trigger'}]->(r)
          } IN TRANSACTIONS OF #{batch_size} ROWS
        CYPHER
      end
      puts "  Created trigger PRODUCES relationships"
    end

    # Create REQUIRES relationships from modules to requirement nodes (batched)
    # Session relationships use platform-qualified IDs: session/{platform}/{session_type}
    def create_requires_relationships(batch_size: DEFAULT_BATCH_SIZE)
      puts "Creating REQUIRES relationships..."

      # Session REQUIRES relationships (session_in values are already {platform}/{session_type})
      session do |session|
        session.run(<<~CYPHER)
          CALL {
            MATCH (m:Module)
            WHERE m.session_in IS NOT NULL
            UNWIND m.session_in AS sess_value
            WITH m, 'session/' + sess_value AS qualified_id
            MATCH (r:Requirement {id: qualified_id})
            MERGE (m)-[:REQUIRES {type: 'session'}]->(r)
          } IN TRANSACTIONS OF #{batch_size} ROWS
        CYPHER
      end
      puts "  Created session REQUIRES relationships"

      # Authentication REQUIRES relationships (authentication_in -> Authentication nodes)
      session do |session|
        session.run(<<~CYPHER)
          CALL {
            MATCH (m:Module)
            WHERE m.authentication_in IS NOT NULL
            UNWIND m.authentication_in AS auth_type
            MATCH (r:Requirement {id: auth_type})
            MERGE (m)-[:REQUIRES {type: 'authentication'}]->(r)
          } IN TRANSACTIONS OF #{batch_size} ROWS
        CYPHER
      end
      puts "  Created authentication REQUIRES relationships"

      # Trigger REQUIRES relationships (trigger_in -> Trigger nodes)
      session do |session|
        session.run(<<~CYPHER)
          CALL {
            MATCH (m:Module)
            WHERE m.trigger_in IS NOT NULL
            UNWIND m.trigger_in AS trigger_type
            MATCH (r:Requirement {id: trigger_type})
            MERGE (m)-[:REQUIRES {type: 'trigger'}]->(r)
          } IN TRANSACTIONS OF #{batch_size} ROWS
        CYPHER
      end
      puts "  Created trigger REQUIRES relationships"
    end

    # Build the complete requirement node model with relationships
    def build_requirement_model(batch_size: DEFAULT_BATCH_SIZE)
      puts "\n" + "=" * 60
      puts "BUILDING REQUIREMENT NODE MODEL"
      puts "=" * 60

      # Step 1: Create all requirement nodes
      create_requirement_nodes(batch_size: batch_size)

      # Step 2: Create PRODUCES relationships
      create_produces_relationships(batch_size: batch_size)

      # Step 3: Create REQUIRES relationships
      create_requires_relationships(batch_size: batch_size)

      # Step 4: Create indexes for efficient querying
      create_requirement_indexes

      puts "\nRequirement model built successfully!"
      puts "=" * 60
    end

    # Create indexes on requirement nodes for query performance
    def create_requirement_indexes
      puts "Creating indexes..."
      session do |session|
        # Index on Requirement id
        begin
          session.run('CREATE INDEX requirement_id IF NOT EXISTS FOR (r:Requirement) ON (r.id)')
        rescue StandardError => e
          puts "  Note: #{e.message}" if e.message.include?('already exists')
        end

        # Indexes on typed requirement labels
        %w[Session Authentication Information Trigger].each do |label|
          begin
            session.run("CREATE INDEX #{label.downcase}_id IF NOT EXISTS FOR (n:#{label}) ON (n.id)")
          rescue StandardError => e
            puts "  Note: #{e.message}" if e.message.include?('already exists')
          end
        end
      end
      puts "  Indexes created"
    end

    # Clear only requirement nodes and their relationships (preserves Module nodes)
    def clear_requirement_model(batch_size: DEFAULT_BATCH_SIZE)
      puts "Clearing requirement model..."
      # Delete in batches to avoid transaction memory limits
      loop do
        deleted = 0
        session do |sess|
          result = sess.run(<<~CYPHER)
            MATCH (r:Requirement)
            WITH r LIMIT #{batch_size}
            DETACH DELETE r
            RETURN count(*) AS deleted
          CYPHER
          deleted = result.first&.[]('deleted') || 0
        end
        break if deleted == 0
      end
      puts "  Requirement nodes and relationships cleared"
    end

    # Get statistics about the requirement model
    def get_requirement_stats
      stats = {}
      session do |session|
        # Count modules
        result = session.run('MATCH (m:Module) RETURN count(m) AS count')
        stats[:modules] = result.first['count']

        # Count requirement nodes by type
        result = session.run(<<~CYPHER)
          MATCH (r:Requirement)
          RETURN labels(r) AS labels, count(r) AS count
        CYPHER
        stats[:requirements] = {}
        result.each do |record|
          # Get the specific type label (not 'Requirement')
          type_label = (record['labels'] - ['Requirement']).first
          stats[:requirements][type_label] = record['count']
        end

        # Count relationships
        result = session.run('MATCH ()-[r:PRODUCES]->() RETURN count(r) AS count')
        stats[:produces_relationships] = result.first['count']

        result = session.run('MATCH ()-[r:REQUIRES]->() RETURN count(r) AS count')
        stats[:requires_relationships] = result.first['count']
      end
      stats
    end

    # =========================================================================
    # MULTI-REQUIREMENT PATHFINDING
    # =========================================================================

    # Find modules that can satisfy ALL requirements of a target module
    # Returns paths through requirement nodes
    def find_enablers_for_module(module_id)
      results = []
      session do |session|
        result = session.run(<<~CYPHER, module_id: module_id)
          MATCH (target:Module {id: $module_id})-[:REQUIRES]->(req:Requirement)
          WITH target, collect(req) AS required_reqs
          MATCH (enabler:Module)-[:PRODUCES]->(req)
          WHERE req IN required_reqs
          WITH target, required_reqs, enabler, collect(req) AS provided_reqs
          WHERE size(provided_reqs) > 0
          RETURN enabler.id AS enabler_id,
                 [r IN provided_reqs | r.id] AS requirements_provided,
                 [r IN required_reqs | r.id] AS requirements_needed,
                 size(provided_reqs) AS match_count,
                 size(required_reqs) AS total_required
          ORDER BY match_count DESC
        CYPHER

        result.each do |record|
          results << {
            enabler_id: record['enabler_id'],
            requirements_provided: record['requirements_provided'],
            requirements_needed: record['requirements_needed'],
            match_count: record['match_count'],
            total_required: record['total_required'],
            satisfies_all: record['match_count'] == record['total_required']
          }
        end
      end
      results
    end

    # Find attack chains that satisfy ALL requirements of a target
    # max_depth: maximum chain length
    # Returns paths where each step provides requirements needed by the next
    def find_attack_chains(target_module_id, max_depth: 5)
      chains = []
      session do |session|
        result = session.run(<<~CYPHER, target_id: target_module_id, max_depth: max_depth)
          MATCH (target:Module {id: $target_id})

          // Get all required requirements for the target
          OPTIONAL MATCH (target)-[:REQUIRES]->(req:Requirement)
          WITH target, collect(DISTINCT req) AS target_requirements

          // Find chains of modules connected through requirements
          MATCH path = (start:Module)-[:PRODUCES|REQUIRES*1..#{max_depth * 2}]->(target)
          WHERE start <> target
            AND all(rel IN relationships(path) WHERE type(rel) IN ['PRODUCES', 'REQUIRES'])

          // Validate the path alternates correctly: Module->PRODUCES->Req, Req<-REQUIRES-Module
          WITH target, target_requirements, path,
               [n IN nodes(path) WHERE n:Module] AS modules_in_path,
               [n IN nodes(path) WHERE n:Requirement] AS reqs_in_path

          // Return paths that could potentially satisfy requirements
          RETURN [m IN modules_in_path | m.id] AS module_chain,
                 [r IN reqs_in_path | r.id] AS requirements_used,
                 length(path) AS path_length
          ORDER BY path_length ASC
          LIMIT 100
        CYPHER

        result.each do |record|
          chains << {
            modules: record['module_chain'],
            requirements: record['requirements_used'],
            length: record['path_length']
          }
        end
      end
      chains
    end

    # Find modules that produce a specific requirement
    def find_producers_of(requirement_id)
      results = []
      session do |session|
        result = session.run(<<~CYPHER, req_id: requirement_id)
          MATCH (m:Module)-[:PRODUCES]->(r:Requirement {id: $req_id})
          RETURN m.id AS module_id, m.type AS module_type
          ORDER BY m.id
        CYPHER

        result.each do |record|
          results << {
            module_id: record['module_id'],
            type: record['module_type']
          }
        end
      end
      results
    end

    # Find modules that require a specific requirement
    def find_consumers_of(requirement_id)
      results = []
      session do |session|
        result = session.run(<<~CYPHER, req_id: requirement_id)
          MATCH (m:Module)-[:REQUIRES]->(r:Requirement {id: $req_id})
          RETURN m.id AS module_id, m.type AS module_type
          ORDER BY m.id
        CYPHER

        result.each do |record|
          results << {
            module_id: record['module_id'],
            type: record['module_type']
          }
        end
      end
      results
    end

    def get_hypergraph_stats
      stats = {}
      session do |session|
        result = session.run(
          'MATCH (n:Module) ' \
          'OPTIONAL MATCH (n)-[:PARTICIPATES_IN]->(h:Hyperedge) ' \
          'WITH count(DISTINCT n) as node_count, count(DISTINCT h) as hyperedge_count ' \
          'MATCH (h:Hyperedge)<-[r:PARTICIPATES_IN]-(n:Module) ' \
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
end
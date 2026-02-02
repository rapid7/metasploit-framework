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
      # Access types - represent how a module obtains access to a target
      # This includes both authentication (credentials) and sessions (established connections)
      # Session IDs are formatted as: session/{platform}/{session_type}
      # e.g., session/windows/meterpreter, session/linux/shell
      access: {
        label: 'Access',
        base_values: %w[shell meterpreter powershell cmd],
        values: %w[authentication/plaintext authentication/hash/net-ntlm authentication/hash/ntlm authentication/kerberos authentication/kerberos/keys authentication/certificate session/ldap session/mssql session/mysql session/postgresql session/smb]
      },
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

    # Named weight levels for PRODUCES relationships.
    # Positive values boost a path, negative values penalize it.
    # Default (unweighted) relationships have weight 0.
    WEIGHT_LEVELS = {
      'highest' => 2.0,
      'high'    => 1.0,
      'normal'  => 0.0,
      'low'     => -1.0,
      'lowest'  => -2.0
    }.freeze

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

      # Extract target_index for composite MERGE key (defaults to -1 for non-exploit modules)
      target_index = neo4j_props.delete('target_index') || -1

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
        # Use composite key (id + target_index) to support per-target exploit nodes
        session.run(
          "MERGE (n:Module {id: #{escape_cypher_string(module_id.to_s)}, target_index: #{target_index.to_i}}) SET n += {#{props_str}}"
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

      # Collect all access requirement values (authentication + session)
      access_values = Set.new

      # Collect trigger requirement values
      trigger_values = Set.new

      session do |session|
        # Get authentication_out values (prefix non-session values with 'authentication/')
        result = session.run(<<~CYPHER)
          MATCH (m:Module)
          WHERE m.authentication_out IS NOT NULL
          UNWIND m.authentication_out AS auth
          RETURN DISTINCT CASE WHEN auth STARTS WITH 'session/' THEN auth ELSE 'authentication/' + auth END AS value
        CYPHER
        result.each { |record| access_values.add(record['value']) }

        # Get authentication_in values (prefix non-session values with 'authentication/')
        result = session.run(<<~CYPHER)
          MATCH (m:Module)
          WHERE m.authentication_in IS NOT NULL
          UNWIND m.authentication_in AS auth
          RETURN DISTINCT CASE WHEN auth STARTS WITH 'session/' THEN auth ELSE 'authentication/' + auth END AS value
        CYPHER
        result.each { |record| access_values.add(record['value']) }

        # Get session_out values (platform-qualified as {platform}/{session_type})
        # Prepend 'session/' to create final ID: session/{platform}/{session_type}
        result = session.run(<<~CYPHER)
          MATCH (m:Module)
          WHERE m.session_out IS NOT NULL
          UNWIND m.session_out AS sess_value
          RETURN DISTINCT 'session/' + sess_value AS value
        CYPHER
        result.each { |record| access_values.add(record['value']) }

        # Get session_in values (platform-qualified as {platform}/{session_type})
        result = session.run(<<~CYPHER)
          MATCH (m:Module)
          WHERE m.session_in IS NOT NULL
          UNWIND m.session_in AS sess_value
          RETURN DISTINCT 'session/' + sess_value AS value
        CYPHER
        result.each { |record| access_values.add(record['value']) }

        # Get trigger_out values
        result = session.run(<<~CYPHER)
          MATCH (m:Module)
          WHERE m.trigger_out IS NOT NULL
          UNWIND m.trigger_out AS trig
          RETURN DISTINCT trig AS value
        CYPHER
        result.each { |record| trigger_values.add(record['value']) }

        # Get trigger_in values
        result = session.run(<<~CYPHER)
          MATCH (m:Module)
          WHERE m.trigger_in IS NOT NULL
          UNWIND m.trigger_in AS trig
          RETURN DISTINCT trig AS value
        CYPHER
        result.each { |record| trigger_values.add(record['value']) }
      end

      puts "  Found #{access_values.size} access requirement values"
      puts "  Found #{trigger_values.size} trigger requirement values"

      # Create access requirement nodes in batches
      access_values.each_slice(batch_size) do |batch|
        session do |session|
          batch.each do |value|
            session.run(
              "MERGE (r:Requirement:Access {id: #{escape_cypher_string(value)}})"
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
    # All PRODUCES relationships get a default weight of 0.
    def create_produces_relationships(batch_size: DEFAULT_BATCH_SIZE)
      puts "Creating PRODUCES relationships..."

      # Access PRODUCES relationships from session_out (values are {platform}/{session_type})
      session do |session|
        session.run(<<~CYPHER)
          CALL {
            MATCH (m:Module)
            WHERE m.session_out IS NOT NULL
            UNWIND m.session_out AS sess_value
            WITH m, 'session/' + sess_value AS qualified_id
            MATCH (r:Requirement {id: qualified_id})
            MERGE (m)-[:PRODUCES {type: 'access', weight: 0}]->(r)
          } IN TRANSACTIONS OF #{batch_size} ROWS
        CYPHER
      end

      # Access PRODUCES relationships from authentication_out (prefix non-session values)
      session do |session|
        session.run(<<~CYPHER)
          CALL {
            MATCH (m:Module)
            WHERE m.authentication_out IS NOT NULL
            UNWIND m.authentication_out AS auth_type
            WITH m, CASE WHEN auth_type STARTS WITH 'session/' THEN auth_type ELSE 'authentication/' + auth_type END AS qualified_id
            MATCH (r:Requirement {id: qualified_id})
            MERGE (m)-[:PRODUCES {type: 'access', weight: 0}]->(r)
          } IN TRANSACTIONS OF #{batch_size} ROWS
        CYPHER
      end
      puts "  Created access PRODUCES relationships"

      # Trigger PRODUCES relationships (trigger_out -> Trigger nodes)
      session do |session|
        session.run(<<~CYPHER)
          CALL {
            MATCH (m:Module)
            WHERE m.trigger_out IS NOT NULL
            UNWIND m.trigger_out AS trigger_type
            MATCH (r:Requirement {id: trigger_type})
            MERGE (m)-[:PRODUCES {type: 'trigger', weight: 0}]->(r)
          } IN TRANSACTIONS OF #{batch_size} ROWS
        CYPHER
      end
      puts "  Created trigger PRODUCES relationships"
    end

    # Apply weight overrides to specific PRODUCES relationships.
    # weight_edits is a hash of module_id => { requirement_id => weight }
    # e.g., { 'auxiliary/admin/kerberos/get_ticket' => { 'authentication/kerberos' => 0.1 } }
    def apply_produces_weights(weight_edits)
      puts "Applying PRODUCES relationship weights..."
      count = 0
      weight_edits.each do |module_id, req_weights|
        req_weights.each do |req_id, weight|
          session do |session|
            result = session.run(<<~CYPHER, module_id: module_id, req_id: req_id, weight: weight.to_f)
              MATCH (m:Module {id: $module_id})-[p:PRODUCES]->(r:Requirement {id: $req_id})
              SET p.weight = $weight
              RETURN count(p) AS updated
            CYPHER
            record = result.first
            if record && record['updated'] > 0
              count += record['updated']
            else
              $stderr.puts "  WARNING: No PRODUCES relationship found for #{module_id} -> #{req_id}"
            end
          end
        end
      end
      puts "  Updated #{count} PRODUCES relationship weights"
    end

    # Create REQUIRES relationships from modules to requirement nodes (batched)
    # Session relationships use platform-qualified IDs: session/{platform}/{session_type}
    def create_requires_relationships(batch_size: DEFAULT_BATCH_SIZE)
      puts "Creating REQUIRES relationships..."

      # Access REQUIRES relationships from session_in (values are {platform}/{session_type})
      session do |session|
        session.run(<<~CYPHER)
          CALL {
            MATCH (m:Module)
            WHERE m.session_in IS NOT NULL
            UNWIND m.session_in AS sess_value
            WITH m, 'session/' + sess_value AS qualified_id
            MATCH (r:Requirement {id: qualified_id})
            MERGE (m)-[:REQUIRES {type: 'access'}]->(r)
          } IN TRANSACTIONS OF #{batch_size} ROWS
        CYPHER
      end

      # Access REQUIRES relationships from authentication_in (prefix non-session values)
      session do |session|
        session.run(<<~CYPHER)
          CALL {
            MATCH (m:Module)
            WHERE m.authentication_in IS NOT NULL
            UNWIND m.authentication_in AS auth_type
            WITH m, CASE WHEN auth_type STARTS WITH 'session/' THEN auth_type ELSE 'authentication/' + auth_type END AS qualified_id
            MATCH (r:Requirement {id: qualified_id})
            MERGE (m)-[:REQUIRES {type: 'access'}]->(r)
          } IN TRANSACTIONS OF #{batch_size} ROWS
        CYPHER
      end
      puts "  Created access REQUIRES relationships"

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
        # Composite index on Module (id + target_index) for unique lookups
        begin
          session.run('CREATE INDEX module_id_target IF NOT EXISTS FOR (m:Module) ON (m.id, m.target_index)')
        rescue StandardError => e
          puts "  Note: #{e.message}" if e.message.include?('already exists')
        end

        # Index on Module id for queries across all targets of a module
        begin
          session.run('CREATE INDEX module_id IF NOT EXISTS FOR (m:Module) ON (m.id)')
        rescue StandardError => e
          puts "  Note: #{e.message}" if e.message.include?('already exists')
        end

        # Index on Requirement id
        begin
          session.run('CREATE INDEX requirement_id IF NOT EXISTS FOR (r:Requirement) ON (r.id)')
        rescue StandardError => e
          puts "  Note: #{e.message}" if e.message.include?('already exists')
        end

        # Indexes on typed requirement labels
        %w[Access Trigger].each do |label|
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
    # max_depth: maximum number of modules in the chain
    # Returns paths where each step provides requirements needed by the next
    #
    # Path pattern: Module -PRODUCES-> Req <-REQUIRES- Module -PRODUCES-> Req ...
    # Since both PRODUCES and REQUIRES point Module->Requirement, we use undirected
    # variable-length paths and validate edge directions explicitly.
    def find_attack_chains(target_module_id, max_depth: 5, limit: 50)
      chains = []
      (2..max_depth).each do |depth|
        # Build: (start)-[:PRODUCES]->(r1)<-[:REQUIRES]-(m2)-[:PRODUCES]->...<-[:REQUIRES]-(target)
        # The chain ends with a REQUIRES edge into the target module
        chain_pattern = '(start:Module)-[:PRODUCES]->'
        module_names = ['start']
        req_names = []
        (1...depth).each do |i|
          req_name = "r#{i}"
          req_names << req_name
          if i < depth - 1
            mod_name = "m#{i + 1}"
            module_names << mod_name
            chain_pattern += "(#{req_name}:Requirement)<-[:REQUIRES]-(#{mod_name}:Module)-[:PRODUCES]->"
          else
            chain_pattern += "(#{req_name}:Requirement)<-[:REQUIRES]-(target)"
          end
        end
        module_names << 'target'

        modules_return = '[' + module_names.map { |m| "#{m}.id" }.join(', ') + ']'
        reqs_return = '[' + req_names.map { |r| "#{r}.id" }.join(', ') + ']'

        session do |session|
          result = session.run(<<~CYPHER, target_id: target_module_id)
            MATCH (target:Module {id: $target_id})
            MATCH #{chain_pattern}
            WHERE start <> target
            RETURN #{modules_return} AS module_chain,
                   #{reqs_return} AS requirements_used,
                   #{depth} AS chain_length
            LIMIT #{limit}
          CYPHER

          result.each do |record|
            chains << {
              modules: record['module_chain'],
              requirements: record['requirements_used'],
              length: record['chain_length']
            }
          end
        end
      end
      chains.sort_by { |c| c[:length] }
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

    # =========================================================================
    # ATTACK CHAIN QUERIES
    # =========================================================================

    # Find chains from modules requiring no access to those producing a target access type.
    # Useful for answering: "How can I get a meterpreter session starting from nothing?"
    #
    # target_access: an Access requirement ID pattern (e.g., 'session/windows/meterpreter',
    #   'authentication/plaintext'). Supports substring matching.
    # max_depth: maximum number of modules in the chain
    # limit: maximum number of chains to return per depth level
    def find_unauthenticated_chains_to(target_access, max_depth: 4, limit: 50)
      results = []
      # Query each depth level separately with explicit directed patterns.
      # This is much faster than undirected variable-length paths because Neo4j
      # can follow edges in known directions without combinatorial explosion.
      (1..max_depth).each do |depth|
        # Build the chain pattern: entry-[:PRODUCES]->(r1)<-[:REQUIRES]-(m2)-[:PRODUCES]->(r2)...->goal
        # Depth 1: (entry)-[:PRODUCES]->(goal)
        # Depth 2: (entry)-[:PRODUCES]->(r1)<-[:REQUIRES]-(m2)-[:PRODUCES]->(goal)
        # Depth 3: (entry)-[:PRODUCES]->(r1)<-[:REQUIRES]-(m2)-[:PRODUCES]->(r2)<-[:REQUIRES]-(m3)-[:PRODUCES]->(goal)
        chain_pattern = '(entry)-[:PRODUCES]->'
        module_names = ['entry']
        req_names = []
        (1...depth).each do |i|
          req_name = "r#{i}"
          mod_name = "m#{i + 1}"
          req_names << req_name
          module_names << mod_name
          chain_pattern += "(#{req_name}:Requirement)<-[:REQUIRES]-(#{mod_name}:Module)-[:PRODUCES]->"
        end
        chain_pattern += '(goal)'

        modules_return = '[' + module_names.map { |m| "#{m}.id" }.join(', ') + ']'
        targets_return = '[' + module_names.map { |m| "#{m}.target_name" }.join(', ') + ']'
        reqs_return = if req_names.empty?
                        '[goal.id]'
                      else
                        '[' + req_names.map { |r| "#{r}.id" }.join(', ') + ', goal.id]'
                      end

        session do |session|
          result = session.run(<<~CYPHER, target: target_access)
            MATCH (entry:Module)
            WHERE NOT (entry)-[:REQUIRES]->(:Access)
            MATCH (goal:Access)
            WHERE goal.id CONTAINS $target
            MATCH #{chain_pattern}
            RETURN #{modules_return} AS chain,
                   #{targets_return} AS target_names,
                   #{reqs_return} AS access_pivots,
                   goal.id AS target,
                   #{depth} AS chain_length
            LIMIT #{limit}
          CYPHER

          result.each do |record|
            results << {
              chain: record['chain'],
              target_names: record['target_names'],
              access_pivots: record['access_pivots'],
              target: record['target'],
              chain_length: record['chain_length']
            }
          end
        end
      end
      results.sort_by { |r| r[:chain_length] }
    end

    # Find credential escalation paths between two access types.
    # Useful for answering: "If I have an NTLM hash, how do I get a kerberos ticket?"
    #
    # from_access: starting Access requirement ID (e.g., 'authentication/hash/ntlm')
    # to_access: goal Access requirement ID (e.g., 'authentication/kerberos')
    # max_depth: maximum number of modules in the chain
    def find_access_escalation(from_access, to_access, max_depth: 4, limit: 50)
      results = []
      (1..max_depth).each do |depth|
        # Build: (first)-[p1:PRODUCES]->...<-[:REQUIRES]-(last)-[pN:PRODUCES]->(end_req)
        # where first REQUIRES start_req
        # Name each PRODUCES relationship to capture weights.
        produces_names = ['p1']
        chain_pattern = '(first)-[p1:PRODUCES]->'
        module_names = ['first']
        req_names = []
        (1...depth).each do |i|
          req_name = "r#{i}"
          mod_name = "m#{i + 1}"
          prod_name = "p#{i + 1}"
          req_names << req_name
          module_names << mod_name
          produces_names << prod_name
          chain_pattern += "(#{req_name}:Requirement)<-[:REQUIRES]-(#{mod_name}:Module)-[#{prod_name}:PRODUCES]->"
        end
        chain_pattern += '(end_req)'

        modules_return = '[' + module_names.map { |m| "#{m}.id" }.join(', ') + ']'
        targets_return = '[' + module_names.map { |m| "#{m}.target_name" }.join(', ') + ']'
        reqs_return = if req_names.empty?
                        '[end_req.id]'
                      else
                        '[' + req_names.map { |r| "#{r}.id" }.join(', ') + ', end_req.id]'
                      end
        weight_sum = produces_names.map { |p| "#{p}.weight" }.join(' + ')

        session do |session|
          result = session.run(<<~CYPHER, from: from_access, to: to_access)
            MATCH (start_req:Access {id: $from})
            MATCH (end_req:Access {id: $to})
            MATCH (first:Module)-[:REQUIRES]->(start_req)
            MATCH #{chain_pattern}
            RETURN #{modules_return} AS chain,
                   #{targets_return} AS target_names,
                   #{reqs_return} AS access_pivots,
                   $from AS from_access,
                   $to AS to_access,
                   #{depth} AS chain_length,
                   #{weight_sum} AS total_weight
            ORDER BY #{weight_sum} DESC
            LIMIT #{limit}
          CYPHER

          result.each do |record|
            results << {
              chain: record['chain'],
              target_names: record['target_names'],
              access_pivots: record['access_pivots'],
              from_access: record['from_access'],
              to_access: record['to_access'],
              chain_length: record['chain_length'],
              total_weight: record['total_weight']
            }
          end
        end
      end
      results.sort_by { |r| [r[:chain_length], -r[:total_weight]] }
    end

    # Find paths from a given access type to satisfy the requirements of a target module.
    # Useful for answering: "I have an NTLM hash, how do I run module X?"
    #
    # from_access: starting Access requirement ID (e.g., 'authentication/hash/ntlm')
    # target_module: the module ID to reach (e.g., 'post/windows/gather/hashdump')
    # max_depth: maximum number of intermediate modules in the chain (not counting the target)
    def find_paths_to_module(from_access, target_module, max_depth: 4, limit: 50)
      results = []

      # First, look up what the target module requires so we can display it
      target_requirements = []
      session do |session|
        result = session.run(<<~CYPHER, target_id: target_module)
          MATCH (target:Module {id: $target_id})-[:REQUIRES]->(req:Requirement)
          RETURN collect(DISTINCT req.id) AS requirements
        CYPHER
        record = result.first
        target_requirements = record['requirements'] if record
      end

      (1..max_depth).each do |depth|
        # Build chain: (first)-[p1:PRODUCES]->...<-[:REQUIRES]-(target)
        # Depth 1: (first)-[p1:PRODUCES]->(r1)<-[:REQUIRES]-(target)
        # Depth 2: (first)-[p1:PRODUCES]->(r1)<-[:REQUIRES]-(m2)-[p2:PRODUCES]->(r2)<-[:REQUIRES]-(target)
        # Name each PRODUCES relationship to capture weights.
        produces_names = ['p1']
        chain_pattern = '(first)-[p1:PRODUCES]->'
        module_names = ['first']
        req_names = []

        (1..depth).each do |i|
          req_name = "r#{i}"
          req_names << req_name
          if i < depth
            mod_name = "m#{i + 1}"
            prod_name = "p#{i + 1}"
            module_names << mod_name
            produces_names << prod_name
            chain_pattern += "(#{req_name}:Requirement)<-[:REQUIRES]-(#{mod_name}:Module)-[#{prod_name}:PRODUCES]->"
          else
            chain_pattern += "(#{req_name}:Requirement)<-[:REQUIRES]-(target)"
          end
        end

        modules_return = '[' + module_names.map { |m| "#{m}.id" }.join(', ') + ']'
        targets_return = '[' + module_names.map { |m| "#{m}.target_name" }.join(', ') + ']'
        reqs_return = '[' + req_names.map { |r| "#{r}.id" }.join(', ') + ']'
        weight_sum = produces_names.map { |p| "#{p}.weight" }.join(' + ')

        session do |session|
          result = session.run(<<~CYPHER, from: from_access, target_id: target_module)
            MATCH (start_req:Access {id: $from})
            MATCH (target:Module {id: $target_id})
            MATCH (first:Module)-[:REQUIRES]->(start_req)
            MATCH #{chain_pattern}
            WHERE first <> target
            RETURN #{modules_return} AS chain,
                   #{targets_return} AS target_names,
                   #{reqs_return} AS requirements_used,
                   #{depth} AS chain_length,
                   #{weight_sum} AS total_weight
            ORDER BY #{weight_sum} DESC
            LIMIT #{limit}
          CYPHER

          result.each do |record|
            results << {
              chain: record['chain'],
              target_names: record['target_names'],
              requirements_used: record['requirements_used'],
              chain_length: record['chain_length'],
              total_weight: record['total_weight']
            }
          end
        end
      end
      {
        target_module: target_module,
        target_requirements: target_requirements,
        paths: results.sort_by { |r| [r[:chain_length], -r[:total_weight]] }
      }
    end

    # Find coercion-to-credential chains: trigger → capture/relay → access.
    # Useful for answering: "What credentials can I get from SMB coercion?"
    #
    # coercion_type: a Trigger requirement ID (e.g., 'coercion/smb', 'coercion')
    def find_coercion_chains(coercion_type = 'coercion/smb')
      results = []
      session do |session|
        result = session.run(<<~CYPHER, coercion: coercion_type)
          // Find the coercion trigger
          MATCH (trigger:Trigger {id: $coercion})

          // Find modules that require this trigger (capture/relay servers)
          MATCH (relay:Module)-[:REQUIRES]->(trigger)

          // Find what access those modules produce
          MATCH (relay)-[:PRODUCES]->(access:Access)

          RETURN relay.id AS module_id,
                 relay.type AS module_type,
                 relay.target_name AS target_name,
                 collect(DISTINCT access.id) AS produces_access
          ORDER BY module_id
        CYPHER

        result.each do |record|
          results << {
            module_id: record['module_id'],
            module_type: record['module_type'],
            target_name: record['target_name'],
            produces_access: record['produces_access']
          }
        end
      end
      results
    end

    # Find full attack narratives: coercion → relay/capture → credential → exploit → session → post.
    # Returns the longest interesting chains in the graph.
    #
    # max_depth: maximum number of modules in the chain
    # platform: optional platform filter (e.g., 'windows') applied to session requirement IDs
    def find_full_attack_paths(max_depth: 6, platform: nil, limit: 25)
      results = []

      (3..max_depth).each do |depth|
        # Build the chain pattern for this depth
        chain_pattern = '(entry)-[:PRODUCES]->'
        module_names = ['entry']
        req_names = []
        (1...depth).each do |i|
          req_name = "r#{i}"
          mod_name = "m#{i + 1}"
          req_names << req_name
          module_names << mod_name
          chain_pattern += "(#{req_name}:Requirement)<-[:REQUIRES]-(#{mod_name}:Module)-[:PRODUCES]->"
        end
        # Final requirement produced by the last module
        final_req = "r#{depth}"
        req_names << final_req
        chain_pattern += "(#{final_req}:Requirement)"

        modules_return = '[' + module_names.map { |m| "#{m}.id" }.join(', ') + ']'
        types_return = '[' + module_names.map { |m| "#{m}.type" }.join(', ') + ']'
        targets_return = '[' + module_names.map { |m| "#{m}.target_name" }.join(', ') + ']'
        reqs_return = '[' + req_names.map { |r| "#{r}.id" }.join(', ') + ']'

        platform_clause = platform ? "WHERE any(req_id IN #{reqs_return} WHERE req_id CONTAINS '#{platform}')" : ""

        session do |session|
          result = session.run(<<~CYPHER)
            MATCH (entry:Module)
            WHERE (entry)-[:PRODUCES]->(:Trigger)
               OR (entry.type = 'exploit' AND NOT (entry)-[:REQUIRES]->(:Access))
            MATCH #{chain_pattern}
            #{platform_clause}
            RETURN #{modules_return} AS chain,
                   #{types_return} AS module_types,
                   #{targets_return} AS target_names,
                   #{reqs_return} AS requirements_used,
                   #{depth} AS chain_length
            LIMIT #{limit}
          CYPHER

          result.each do |record|
            results << {
              chain: record['chain'],
              module_types: record['module_types'],
              target_names: record['target_names'],
              requirements_used: record['requirements_used'],
              chain_length: record['chain_length']
            }
          end
        end
      end
      results.sort_by { |r| -r[:chain_length] }
    end

    # Find all modules reachable from a given access type, traversing through
    # the requirement graph. Answers: "What can I do if I have X?"
    #
    # access_id: an Access requirement ID (e.g., 'authentication/hash/ntlm',
    #   'session/windows/meterpreter')
    # max_depth: how many hops to traverse
    def find_reachable_from(access_id, max_depth: 3, limit: 50)
      results = []
      seen = Set.new
      (1..max_depth).each do |depth|
        # Build: (start)<-[:REQUIRES]-(m1)-[:PRODUCES]->(r1)<-[:REQUIRES]-(m2)...
        # Depth 1: just (start)<-[:REQUIRES]-(m1)
        # Depth 2: (start)<-[:REQUIRES]-(m1)-[:PRODUCES]->(r1)<-[:REQUIRES]-(m2)
        chain_pattern = '(start)<-[:REQUIRES]-(m1:Module)'
        module_names = ['m1']
        (2..depth).each do |i|
          mod_name = "m#{i}"
          module_names << mod_name
          chain_pattern += "-[:PRODUCES]->(:Requirement)<-[:REQUIRES]-(#{mod_name}:Module)"
        end

        reached_var = module_names.last

        session do |session|
          result = session.run(<<~CYPHER, access: access_id)
            MATCH (start:Access {id: $access})
            MATCH #{chain_pattern}
            WITH DISTINCT #{reached_var} AS reached
            OPTIONAL MATCH (reached)-[:PRODUCES]->(product:Requirement)
            RETURN reached.id AS module_id,
                   reached.type AS module_type,
                   reached.target_name AS target_name,
                   #{depth} AS distance,
                   collect(DISTINCT product.id) AS produces
            ORDER BY module_id
            LIMIT #{limit}
          CYPHER

          result.each do |record|
            next if seen.include?(record['module_id'])

            seen.add(record['module_id'])
            results << {
              module_id: record['module_id'],
              module_type: record['module_type'],
              target_name: record['target_name'],
              distance: record['distance'],
              produces: record['produces']
            }
          end
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
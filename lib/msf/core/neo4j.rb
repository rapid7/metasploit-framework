require 'neo4j/driver'
require 'uri'

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

      # Named weight levels for PRODUCES relationships. Positive values boost a path, negative values penalize it.
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

      def initialize(connection_string: 'neo4j://neo4j:neo4j@localhost:7687')
        parsed = URI.parse(connection_string)
        uri = "#{parsed.scheme}://#{parsed.host}:#{parsed.port}"
        auth_tokens = ::Neo4j::Driver::AuthTokens.basic(
          (parsed.user || 'neo4j'),
          (parsed.password || 'neo4j')
        )
        @driver = ::Neo4j::Driver::GraphDatabase.driver(uri, auth_tokens)
      end

      def close
        @driver.close
      end

      def clear_database(batch_size: DEFAULT_BATCH_SIZE)
        batch_delete(<<~CYPHER)
          MATCH (n)
          WITH n LIMIT #{batch_size}
          DETACH DELETE n
          RETURN count(*) AS deleted
        CYPHER
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
        # Exclude nil values — omitting a property is cleaner than setting it to NULL
        props_str = neo4j_props.reject { |_, v| v.nil? }.map do |key, value|
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

        with_session do |session|
          # Use composite key (id + target_index) to support per-target exploit nodes
          session.run(
            "MERGE (n:Module {id: #{escape_cypher_string(module_id.to_s)}, target_index: #{target_index.to_i}}) SET n += {#{props_str}}"
          )
        end
      end

      def update_module_properties(module_id, additions: {}, removals: {})
        # Validate that the module exists
        module_exists = false
        with_session do |session|
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

          with_session do |session|
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

            with_session do |session|
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

      # Create all requirement nodes from module properties in batches
      # Session requirements are platform-qualified: session/{platform}/{session_type}
      def create_requirement_nodes(batch_size: DEFAULT_BATCH_SIZE)
        # Collect all access requirement values (authentication + session)
        access_values = Set.new

        # Collect trigger requirement values
        trigger_values = Set.new

        with_session do |session|
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

        # Create access requirement nodes in batches
        access_values.each_slice(batch_size) do |batch|
          with_session do |session|
            batch.each do |value|
              session.run(
                "MERGE (r:Requirement:Access {id: #{escape_cypher_string(value)}})"
              )
            end
          end
        end

        # Create trigger requirement nodes in batches
        trigger_values.each_slice(batch_size) do |batch|
          with_session do |session|
            batch.each do |value|
              session.run(
                "MERGE (r:Requirement:Trigger {id: #{escape_cypher_string(value)}})"
              )
            end
          end
        end

        { access_count: access_values.size, trigger_count: trigger_values.size }
      end

      # Create PRODUCES relationships from modules to requirement nodes (batched)
      # Session relationships use platform-qualified IDs: session/{platform}/{session_type}
      # All PRODUCES relationships get a default weight of 0.
      def create_produces_relationships(batch_size: DEFAULT_BATCH_SIZE)
        # Access PRODUCES relationships from session_out (values are {platform}/{session_type})
        with_session do |session|
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
        with_session do |session|
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

        # Trigger PRODUCES relationships (trigger_out -> Trigger nodes)
        with_session do |session|
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
      end

      # Apply weight overrides to specific PRODUCES relationships.
      # weight_edits is a hash of module_id => { requirement_id => weight }
      # e.g., { 'auxiliary/admin/kerberos/get_ticket' => { 'authentication/kerberos' => 0.1 } }
      def apply_produces_weights(weight_edits)
        count = 0
        with_session do |session|
          weight_edits.each do |module_id, req_weights|
            req_weights.each do |req_id, weight|
              result = session.run(<<~CYPHER, module_id: module_id, req_id: req_id, weight: weight.to_f)
                MATCH (m:Module {id: $module_id})-[p:PRODUCES]->(r:Requirement {id: $req_id})
                SET p.weight = $weight
                RETURN count(p) AS updated
              CYPHER
              record = result.first
              if record && record['updated'] > 0
                count += record['updated']
              else
                wlog "No PRODUCES relationship found for #{module_id} -> #{req_id}"
              end
            end
          end
        end
        count
      end

      # Create REQUIRES relationships from modules to requirement nodes (batched)
      # Session relationships use platform-qualified IDs: session/{platform}/{session_type}
      def create_requires_relationships(batch_size: DEFAULT_BATCH_SIZE)
        # Access REQUIRES relationships from session_in (values are {platform}/{session_type})
        with_session do |session|
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
        with_session do |session|
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

        # Trigger REQUIRES relationships (trigger_in -> Trigger nodes)
        with_session do |session|
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
      end

      # Build the complete requirement node model with relationships
      def build_requirement_model(batch_size: DEFAULT_BATCH_SIZE)
        # Step 1: Create all requirement nodes
        stats = create_requirement_nodes(batch_size: batch_size)

        # Step 2: Create PRODUCES relationships
        create_produces_relationships(batch_size: batch_size)

        # Step 3: Create REQUIRES relationships
        create_requires_relationships(batch_size: batch_size)

        # Step 4: Create indexes for efficient querying
        create_requirement_indexes

        stats
      end

      # Create indexes on requirement nodes for query performance
      def create_requirement_indexes
        with_session do |session|
          # Composite index on Module (id + target_index) for unique lookups
          session.run('CREATE INDEX module_id_target IF NOT EXISTS FOR (m:Module) ON (m.id, m.target_index)')

          # Index on Module id for queries across all targets of a module
          session.run('CREATE INDEX module_id IF NOT EXISTS FOR (m:Module) ON (m.id)')

          # Index on Requirement id
          session.run('CREATE INDEX requirement_id IF NOT EXISTS FOR (r:Requirement) ON (r.id)')

          # Indexes on typed requirement labels
          %w[Access Trigger].each do |label|
            session.run("CREATE INDEX #{label.downcase}_id IF NOT EXISTS FOR (n:#{label}) ON (n.id)")
          end
        end
      end

      # Clear only requirement nodes and their relationships (preserves Module nodes)
      def clear_requirement_model(batch_size: DEFAULT_BATCH_SIZE)
        batch_delete(<<~CYPHER)
          MATCH (r:Requirement)
          WITH r LIMIT #{batch_size}
          DETACH DELETE r
          RETURN count(*) AS deleted
        CYPHER
      end

      # Get statistics about the requirement model
      def get_requirement_stats
        stats = {}
        with_session do |session|
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

          # Include 'goal' so we also check the last intermediate req -> goal transition
          consistency_conditions = session_platform_consistency_conditions(req_names + ['goal'])
          chain_where = consistency_conditions.empty? ? '' : "WHERE #{consistency_conditions.join("\nAND ")}"

          with_session do |session|
            result = session.run(<<~CYPHER, target: target_access)
              MATCH (entry:Module)
              WHERE NOT (entry)-[:REQUIRES]->(:Requirement)
              MATCH (goal:Access)
              WHERE goal.id CONTAINS $target
              MATCH #{chain_pattern}
              #{chain_where}
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

          # Check consistency between intermediate reqs and end_req; start_req is user-chosen so excluded
          consistency_conditions = session_platform_consistency_conditions(req_names + ['end_req'])
          chain_where = consistency_conditions.empty? ? '' : "WHERE #{consistency_conditions.join("\nAND ")}"

          with_session do |session|
            result = session.run(<<~CYPHER, from: from_access, to: to_access)
              MATCH (start_req:Access {id: $from})
              MATCH (end_req:Access {id: $to})
              MATCH (first:Module)-[:REQUIRES]->(start_req)
              MATCH #{chain_pattern}
              #{chain_where}
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
        with_session do |session|
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

          # Include start_req to catch modules that take e.g. a Windows session and produce a Linux one
          where_parts = ['first <> target'] + session_platform_consistency_conditions(['start_req'] + req_names)
          chain_where = "WHERE #{where_parts.join("\nAND ")}"

          with_session do |session|
            result = session.run(<<~CYPHER, from: from_access, target_id: target_module)
              MATCH (start_req:Access {id: $from})
              MATCH (target:Module {id: $target_id})
              MATCH (first:Module)-[:REQUIRES]->(start_req)
              MATCH #{chain_pattern}
              #{chain_where}
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
        with_session do |session|
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

          where_parts = session_platform_consistency_conditions(req_names)
          where_parts << "any(req_id IN #{reqs_return} WHERE req_id CONTAINS '#{platform}')" if platform
          chain_where = where_parts.empty? ? '' : "WHERE #{where_parts.join("\nAND ")}"

          with_session do |session|
            result = session.run(<<~CYPHER)
              MATCH (entry:Module)
              WHERE (entry)-[:PRODUCES]->(:Trigger)
                 OR (entry.type = 'exploit' AND NOT (entry)-[:REQUIRES]->(:Access))
              MATCH #{chain_pattern}
              #{chain_where}
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

          with_session do |session|
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

      private

      # Returns Cypher boolean conditions (to be joined with AND) that enforce platform
      # consistency between adjacent session requirement nodes in a chain.
      # When two consecutive requirement nodes are both session requirements
      # (e.g., session/windows/meterpreter), they must share the same platform segment.
      # This prevents nonsensical paths like session/windows/X -> session/linux/Y
      # being chained through a single module without an explicit cross-platform mechanism.
      #
      # req_var_names: ordered list of Cypher variable names for requirement nodes in the chain
      def session_platform_consistency_conditions(req_var_names)
        req_var_names.each_cons(2).map do |ra, rb|
          "(NOT #{ra}.id STARTS WITH 'session/' OR NOT #{rb}.id STARTS WITH 'session/' OR split(#{ra}.id, '/')[1] = split(#{rb}.id, '/')[1])"
        end
      end

      def escape_cypher_string(str)
        # Escape single quotes and backslashes for Cypher string literals
        escaped = str.to_s.gsub('\\', '\\\\\\\\').gsub("'", "\\\\'")
        "'#{escaped}'"
      end

      def with_session(&block)
        @driver.session(&block)
      end

      def batch_delete(cypher)
        loop do
          deleted = 0
          with_session { |sess| deleted = sess.run(cypher).first&.[]('deleted') || 0 }
          break if deleted == 0
        end
      end
    end
  end
end

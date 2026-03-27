require 'did_you_mean'
require 'msfenv'
require 'uri'

require 'rex'
require 'msf/core/constants'
require Rails.root.join('app/models/application_record')
require Rails.root.join('app/validators/metasploit/framework/executable_path_validator')
require Rails.root.join('app/validators/metasploit/framework/file_path_validator')

require_relative '../msf/core/neo4j'

def load_platform_mappings(transforms)
  result = {}
  mappings = transforms.fetch('platform_edits', {})
  mappings.each_pair do |k, v|
    # Use lowercase keys and values to match platform_property's lowercase lookups
    result[Msf::Platform.find_platform(k).realname.downcase] = v.map { Msf::Platform.find_platform(_1).realname.downcase }
  end

  result
end

def platform_property(mod_ins)
  # Use target-specific platform if available, otherwise fall back to module-level
  platform_list = ((mod_ins.respond_to?(:target) && mod_ins.target&.platform) || mod_ins.platform)
  platform_set = platform_list.names.map(&:downcase).to_set
  result = Set.new

  mapped_platforms = platform_set & ::PLATFORM_MAPPING.keys.to_set
  unmapped_platforms = platform_set - mapped_platforms

  if unmapped_platforms.empty?
    unless mod_ins.type == ::Msf::MODULE_PAYLOAD
      _, platform_name, path = mod_ins.fullname.split('/', 3)
      if path && platform_name != 'multi'
        result.add(Msf::Platform.find_platform(platform_name).realname.downcase)
      elsif path
        mapped_platforms.each do |platform|
          result.merge(::PLATFORM_MAPPING[platform].map(&:downcase))
        end
      end
    else
      mapped_platforms.each do |platform|
        result.merge(::PLATFORM_MAPPING[platform].map(&:downcase))
      end
    end
  else
    # if there's an explicit platform that's not mapped because it's a language, then assume that's accurate
    unmapped_platforms.each do |platform|
      result.add(platform.to_s.downcase)
    end
  end

  result.delete('unknown')
  result.empty? ? nil : result.to_a
end

def authentication_in_property(mod_ins)
  result = Set.new
  %w[ Winrm LDAP SMB Mssql ].each do |prefix|
    next unless (option = mod_ins.datastore.options.fetch("#{prefix}::Auth", nil))

    result.merge(option.enums)
  end

  if result.empty?
    if (option = mod_ins.datastore.options.fetch('PASSWORD', nil))
      if option.required
        # fixme: this is gonna get fooled by modules that need PASSWORD set for the creation of an account
        result.add('plaintext')
      end
    end
  else
    result.add('hash/ntlm') if result.delete?('ntlm')
    # LDAP calls it schannel, but we're going to rename it to "certificate" to be more generic,
    # the point is you're authenticating with a certificate
    result.add('certificate') if result.delete?('schannel')
  end

  # check if we can use a session for access
  session_auth = (session_in_property(mod_ins) || []) & PROTOCOL_SESSIONS
  unless session_auth.empty?
    result.merge(session_auth.map { "session/#{_1}" })
  end

  # If a module can authenticate with a hash, e.g. NTLM, then assume we can calculate the hash given a plaintext
  # password. In practice, this should really only add 'plaintext' in cases where 'ntlm' is listed but 'plaintext' is
  # not.
  result.add('plaintext') if result.any? { _1.start_with?('hash/') }

  result.delete('auto')
  result.delete('none')
  result.empty? ? nil : result.to_a
end

def session_in_property(mod_ins)
  result = Set.new

  if mod_ins.is_a?(Msf::PostMixin)
    if (platforms = platform_property(mod_ins)).nil?
      if mod_ins.session_types.include?('meterpreter')
        # all the platforms meterpreter will run on after taking into consideration things like python, php and java
        # which will fingerprint it once running and return the real platform for post-module matching
        platforms = %w[ android apple_ios linux osx unix windows ]
      end
    end

    unless platforms.nil?
      result.merge(platforms.product(mod_ins.session_types).map { _1.join('/') })
    end
  end

  result.add('ldap') if mod_ins.is_a?(Msf::OptionalSession::LDAP)
  result.add('mssql') if mod_ins.is_a?(Msf::OptionalSession::MSSQL)
  result.add('mysql') if mod_ins.is_a?(Msf::OptionalSession::MySQL)
  result.add('postgresql') if mod_ins.is_a?(Msf::OptionalSession::PostgreSQL)
  result.add('smb') if mod_ins.is_a?(Msf::OptionalSession::SMB)

  result.empty? ? nil : result.to_a
end

# Returns the session types produced by the currently selected target of an exploit module.
# The caller is responsible for setting datastore['TARGET'] before calling this.
def session_out_property(mod_ins)
  result = Set.new

  mod_ins.compatible_payloads.each do |ref_name, klass|
    payload_mod_ins = klass.new
    next unless payload_mod_ins.platform
    next unless payload_mod_ins.session
    next unless payload_mod_ins.session.type.end_with?('shell') || payload_mod_ins.session.type == 'meterpreter'

    result.merge(payload_mod_ins.platform.names.reject(&:empty?).map(&:downcase).product([payload_mod_ins.session.type]).map { _1.join('/') })
  end

  result.empty? ? nil : result.to_a
end

def trigger_in_property(mod_ins)
  result = Set.new

  result.add('interaction/file-open') if mod_ins.fullname.include?('/fileformat/')

  result.empty? ? nil : result.to_a
end

def access_in_property(mod_ins)
  result = Set.new

  (authentication_in_property(mod_ins) || []).each do |val|
    result.add(val.start_with?('session/') ? val : "authentication/#{val}")
  end

  (session_in_property(mod_ins) || []).each do |val|
    result.add("session/#{val}")
  end

  result.empty? ? nil : result.to_a
end

def access_out_property(mod_ins)
  result = Set.new

  (session_out_property(mod_ins) || []).each do |val|
    result.add("session/#{val}")
  end

  result.empty? ? nil : result.to_a
end

NEO4J_URL = ENV['NEO4J_URL'] || 'neo4j://neo4j:neo4j@localhost:7687'
NEO4J_BROWSER_URL = "http://#{URI.parse(NEO4J_URL).host}:7474"

PROTOCOL_SESSIONS = %w[ ldap mssql mysql postgresql smb ]
# Load Neo4j transforms configuration
TRANSFORMS_FILE = Rails.root.join('data/neo4j/module_graph/transforms.yml')
TRANSFORMS_CONFIG = File.exist?(TRANSFORMS_FILE) ? YAML.load_file(TRANSFORMS_FILE) : {}
PLATFORM_MAPPING = load_platform_mappings(TRANSFORMS_CONFIG)

class ModuleImporter
  attr_reader :framework
  def initialize
    create_opts = {}
    create_opts[:module_types] = [
      ::Msf::MODULE_AUX, ::Msf::MODULE_EXPLOIT, ::Msf::MODULE_PAYLOAD, ::Msf::MODULE_POST
    ]
    @framework = ::Msf::Simple::Framework.create(create_opts)
  end

  def import_module(graph, mod_cls)
    mod_ins = mod_cls.new

    case mod_cls.type
    when ::Msf::MODULE_AUX
      properties = {
        type: mod_cls.type,
        target_index: -1,
        disclosure_date: mod_ins.disclosure_date&.strftime('%Y-%m-%d'),
        access_in: access_in_property(mod_ins)
      }
      graph.create_module(mod_cls.fullname, **properties)
    when ::Msf::MODULE_EXPLOIT
      mod_ins.targets.each_with_index do |target, idx|
        mod_ins.datastore['TARGET'] = idx
        properties = {
          type: mod_cls.type,
          target_index: idx,
          target_name: target.name,
          disclosure_date: mod_ins.disclosure_date&.strftime('%Y-%m-%d'),
          access_in: access_in_property(mod_ins),
          platform: platform_property(mod_ins),
          access_out: access_out_property(mod_ins),
          trigger_in: trigger_in_property(mod_ins)
        }
        graph.create_module(mod_cls.fullname, **properties)
      end
    when ::Msf::MODULE_POST
      properties = {
        type: mod_cls.type,
        target_index: -1,
        disclosure_date: mod_ins.disclosure_date&.strftime('%Y-%m-%d'),
        platform: platform_property(mod_ins),
        access_in: access_in_property(mod_ins)
      }
      graph.create_module(mod_cls.fullname, **properties)
    end
  end
end

namespace :module_graph do
  def with_graph
    graph = Msf::Neo4j::Graph.new(connection_string: NEO4J_URL)
    begin
      yield graph
    rescue Neo4j::Driver::Exceptions::AuthenticationException
      abort "Neo4j authentication failed. Check the credentials in NEO4J_URL. (currently: #{NEO4J_URL})"
    rescue Neo4j::Driver::Exceptions::ServiceUnavailableException
      abort "Could not connect to Neo4j. Is it running? (currently: #{NEO4J_URL})"
    ensure
      graph.close
    end
  end

  desc "Delete all data from Neo4j database"
  task :clean do
    puts "Clearing Neo4j database..."
    with_graph do |graph|
      graph.clear_database
    end
    puts "Done!"
  end

  desc "Generate module graph (import modules, apply edits, build requirement model)"
  task :generate do
    puts "Generating module graph..."
    with_graph do |graph|
      puts "Phase 1: Importing modules..."
      importer = ModuleImporter.new

      modules_imported = 0
      importer.framework.modules.each do |name, mod_cls|
        if mod_cls.nil?
          puts "  No module object for: #{name}"
          next
        end
        begin
          importer.import_module(graph, mod_cls)
        rescue Interrupt
          exit
        rescue Neo4j::Driver::Exceptions::ServiceUnavailableException, Neo4j::Driver::Exceptions::AuthenticationException
          raise
        rescue StandardError => e
          elog "Failed to import #{mod_cls.fullname}"
          elog "#{e.class}: #{e.message}".indent(2)
          elog e.backtrace.join("\n").indent(2)
        else
          modules_imported += 1
        end
      end
      puts "Phase 1: Completed importing #{modules_imported} modules.\n"

      # Phase 2: Apply artisanal properties from transforms file
      puts "Phase 2: Applying module edits..."
      module_edits = TRANSFORMS_CONFIG['module_edits'] || {}
      result = { weight_edits: {}, edit_errors: [], weight_errors: [], artisanal_count: 0 }

      if module_edits.any?
        result = apply_module_edits(graph, module_edits)
        puts "Phase 2: Applied module edits to #{result[:artisanal_count]} modules."
        unless result[:edit_errors].empty?
          puts "\nErrors encountered:"
          result[:edit_errors].each { |error| puts "  - #{error}" }
          raise "Module edits validation failed. Fix the errors above in #{TRANSFORMS_FILE}"
        end
        unless result[:weight_errors].empty?
          puts "\nWeight configuration errors:"
          result[:weight_errors].each { |error| puts "  - #{error}" }
          raise "Weight configuration failed. Fix the errors above in #{TRANSFORMS_FILE}"
        end
      else
        puts "No module edits found in #{TRANSFORMS_FILE}"
      end
      puts "Phase 2: Completed.\n"

      # Phase 3: Build requirement node model
      puts "Phase 3: Building requirement model..."
      stats = graph.build_requirement_model
      puts "  Found #{stats[:access_count]} access requirement nodes"
      puts "  Found #{stats[:trigger_count]} trigger requirement nodes"
      puts "Phase 3: Completed.\n"

      # Phase 4: Apply PRODUCES relationship weights extracted from Phase 2
      if module_edits.any? && result[:weight_edits].any?
        puts "Phase 4: Applying PRODUCES relationship weights..."
        count = graph.apply_produces_weights(result[:weight_edits])
        puts "  Updated #{count} PRODUCES relationship weights"
        puts "Phase 4: Completed.\n"
      end

      puts "Generation complete!"
      puts "View at #{NEO4J_BROWSER_URL}"
    end
  end

  desc "Show requirement model statistics"
  task :requirement_stats do
    puts "Fetching requirement model statistics..."
    with_graph do |graph|
      stats = graph.get_requirement_stats

      puts "\n" + "=" * 60
      puts "REQUIREMENT MODEL STATISTICS"
      puts "=" * 60

      if stats[:modules] == 0
        puts "No data in requirement model"
      else
        puts "Modules: #{stats[:modules].to_s.gsub(/\B(?=(...)*\b)/, ',')}"
        puts "\nRequirement nodes by type:"
        if stats[:requirements]
          stats[:requirements].each do |type, count|
            puts "  #{type}: #{count}"
          end
        end
        puts "\nRelationships:"
        puts "  PRODUCES: #{stats[:produces_relationships].to_s.gsub(/\B(?=(...)*\b)/, ',')}"
        puts "  REQUIRES: #{stats[:requires_relationships].to_s.gsub(/\B(?=(...)*\b)/, ',')}"
      end

      puts "=" * 60
    end
  end

  desc "Regenerate module graph (clean + generate)"
  task :regenerate => [:clean, :generate]

  desc "Re-apply module edits and rebuild the requirement model without re-importing modules"
  task :reapply_transforms do
    with_graph do |graph|
      # Step 1: Clear existing requirement model
      puts "Clearing requirement model..."
      graph.clear_requirement_model

      # Step 2: Re-apply module edits from transforms
      puts "\nApplying module edits..."
      module_edits = TRANSFORMS_CONFIG['module_edits'] || {}
      result = { weight_edits: {}, edit_errors: [], weight_errors: [], artisanal_count: 0 }

      if module_edits.any?
        result = apply_module_edits(graph, module_edits)

        puts "Applied module edits to #{result[:artisanal_count]} modules."
        unless result[:edit_errors].empty?
          puts "\nErrors encountered:"
          result[:edit_errors].each { |error| puts "  - #{error}" }
          raise "Module edits validation failed. Fix the errors above in #{TRANSFORMS_FILE}"
        end
        unless result[:weight_errors].empty?
          puts "\nWeight configuration errors:"
          result[:weight_errors].each { |error| puts "  - #{error}" }
          raise "Weight configuration failed. Fix the errors above in #{TRANSFORMS_FILE}"
        end
      end

      # Step 3: Rebuild requirement model
      puts "\nRebuilding requirement model..."
      stats = graph.build_requirement_model
      puts "  Found #{stats[:access_count]} access requirement nodes"
      puts "  Found #{stats[:trigger_count]} trigger requirement nodes"

      # Step 4: Apply weights
      if module_edits.any? && result[:weight_edits].any?
        puts "\nApplying PRODUCES relationship weights..."
        count = graph.apply_produces_weights(result[:weight_edits])
        puts "  Updated #{count} PRODUCES relationship weights"
      end

      puts "\nRefresh complete!"
      puts "View at #{NEO4J_BROWSER_URL}"
    end
  end

  desc "List all requirement nodes in a table format to help spot typos and modeling errors"
  task :list_requirements do
    puts "Fetching requirement nodes..."
    with_graph do |graph|
      requirements = []
      graph.instance_eval do
        with_session do |sess|
          result = sess.run(<<~CYPHER)
            MATCH (r:Requirement)
            OPTIONAL MATCH (producer:Module)-[:PRODUCES]->(r)
            OPTIONAL MATCH (consumer:Module)-[:REQUIRES]->(r)
            WITH r, labels(r) AS labels,
                 count(DISTINCT producer) AS producers,
                 count(DISTINCT consumer) AS consumers
            RETURN [l IN labels WHERE l <> 'Requirement'][0] AS type,
                   r.id AS id,
                   producers,
                   consumers
            ORDER BY type, id
          CYPHER

          result.each do |record|
            requirements << {
              type: record['type'] || 'Unknown',
              id: record['id'],
              producers: record['producers'],
              consumers: record['consumers']
            }
          end
        end
      end

      if requirements.empty?
        puts "No requirement nodes found. Run 'rake module_graph:generate' first."
      else
        # Calculate column widths
        type_width = [requirements.map { |r| r[:type].to_s.length }.max, 'Type'.length].max
        id_width = [requirements.map { |r| r[:id].to_s.length }.max, 'Requirement ID'.length].max
        prod_width = 9  # "Producers"
        cons_width = 9  # "Consumers"

        # Print header
        puts
        puts "=" * (type_width + id_width + prod_width + cons_width + 13)
        puts "REQUIREMENT NODES"
        puts "=" * (type_width + id_width + prod_width + cons_width + 13)
        puts
        header = "| %-#{type_width}s | %-#{id_width}s | %#{prod_width}s | %#{cons_width}s |" % ['Type', 'Requirement ID', 'Producers', 'Consumers']
        puts header
        puts "|" + "-" * (type_width + 2) + "|" + "-" * (id_width + 2) + "|" + "-" * (prod_width + 2) + "|" + "-" * (cons_width + 2) + "|"

        # Print rows
        requirements.each do |req|
          row = "| %-#{type_width}s | %-#{id_width}s | %#{prod_width}d | %#{cons_width}d |" % [
            req[:type],
            req[:id],
            req[:producers],
            req[:consumers]
          ]
          puts row
        end

        puts "|" + "-" * (type_width + 2) + "|" + "-" * (id_width + 2) + "|" + "-" * (prod_width + 2) + "|" + "-" * (cons_width + 2) + "|"

        # Summary by type
        puts
        puts "Summary by type:"
        type_counts = requirements.group_by { |r| r[:type] }.transform_values(&:count)
        type_counts.each do |type, count|
          puts "  #{type}: #{count}"
        end
        puts "  Total: #{requirements.count}"

        # Warnings for potential issues
        orphaned_producers = requirements.select { |r| r[:consumers] == 0 }
        orphaned_consumers = requirements.select { |r| r[:producers] == 0 }

        if orphaned_producers.any?
          puts
          puts "Warning: #{orphaned_producers.count} requirements have no consumers (nothing REQUIRES them):"
          orphaned_producers.each { |r| puts "  - #{r[:type]}: #{r[:id]}" }
        end

        if orphaned_consumers.any?
          puts
          puts "Warning: #{orphaned_consumers.count} requirements have no producers (nothing PRODUCES them):"
          orphaned_consumers.each { |r| puts "  - #{r[:type]}: #{r[:id]}" }
        end
      end

      puts
    end
  end

  desc 'Inspect a module node and its relationships (e.g., MODULE=exploit/windows/smb/ms17_010_eternalblue)'
  task :inspect_module do
    module_id = ENV['MODULE']
    abort 'Usage: rake module_graph:inspect_module MODULE=exploit/windows/smb/ms17_010_eternalblue' unless module_id

    with_graph do |graph|
      nodes = []
      graph.instance_eval do
        with_session do |sess|
          result = sess.run(<<~CYPHER, module_id: module_id)
            MATCH (m:Module {id: $module_id})
            OPTIONAL MATCH (m)-[pr:PRODUCES]->(produced:Requirement)
            OPTIONAL MATCH (m)-[rr:REQUIRES]->(required:Requirement)
            WITH m, labels(m) AS node_labels,
                 collect(DISTINCT {id: produced.id, labels: labels(produced), weight: pr.weight}) AS produces,
                 collect(DISTINCT {id: required.id, labels: labels(required)}) AS requires
            RETURN m, node_labels, produces, requires
            ORDER BY m.target_index
          CYPHER

          result.each do |record|
            nodes << {
              props: record['m'].properties,
              labels: record['node_labels'],
              produces: record['produces'].reject { |r| r['id'].nil? },
              requires: record['requires'].reject { |r| r['id'].nil? }
            }
          end
        end
      end

      if nodes.empty?
        puts "No module found with id: #{module_id}"
      else
        puts "\n" + ('=' * 70)
        puts "MODULE: #{module_id}"
        puts '=' * 70

        nodes.each do |node|
          props = node[:props]
          target_index = props[:target_index]
          has_targets = nodes.any? { |n| n[:props][:target_index] != -1 }

          puts "\n--- Target #{target_index}: #{props[:target_name] || '(unnamed)'} ---" if has_targets && target_index != -1

          # Print properties (excluding id and target_index which are shown above)
          skip_keys = %i[target_index target_name id]
          props.each do |key, value|
            next if skip_keys.include?(key)
            next if value.nil?

            value_str = value.is_a?(Array) ? value.join(', ') : value.to_s
            puts format('  %-20<key>s %<value>s', key: "#{key}:", value: value_str)
          end

          # Print PRODUCES relationships
          if node[:produces].any?
            puts format('  %-20<key>s', key: 'produces:')
            node[:produces].sort_by { |r| r['id'] }.each do |req|
              type_label = (req['labels'] - ['Requirement']).first || 'Unknown'
              weight_str = req['weight'] && req['weight'] != 0 ? " (weight: #{req['weight']})" : ''
              puts "    [#{type_label}] #{req['id']}#{weight_str}"
            end
          end

          # Print REQUIRES relationships
          next unless node[:requires].any?

          puts format('  %-20<key>s', key: 'requires:')
          node[:requires].sort_by { |r| r['id'] }.each do |req|
            type_label = (req['labels'] - ['Requirement']).first || 'Unknown'
            puts "    [#{type_label}] #{req['id']}"
          end
        end

        puts "\n" + ('=' * 70)
        puts "#{nodes.size} node(s) found"
      end
    end
  end

  # =========================================================================
  # ATTACK CHAIN QUERIES
  # =========================================================================

  # Format a module name with its target for display
  def format_module(mod_id, target_name)
    target_name ? "#{mod_id} (target: #{target_name})" : mod_id.to_s
  end

  # Validate a requirement ID argument against the database, aborting with suggestions on mismatch.
  # match: :exact  - the input must equal a requirement ID
  # match: :contains - at least one requirement ID must contain the input as a substring (mirrors Cypher CONTAINS)
  def validate_requirement_id(graph, input, label: nil, match: :exact)
    all_ids = []
    graph.instance_eval do
      with_session do |sess|
        cypher = label ? "MATCH (r:Requirement:#{label}) RETURN r.id AS id" : 'MATCH (r:Requirement) RETURN r.id AS id'
        sess.run(cypher).each { |record| all_ids << record['id'] }
      end
    end

    valid = case match
            when :exact    then all_ids.include?(input)
            when :contains then all_ids.any? { |id| id.include?(input) }
            end
    return if valid

    # Prefer IDs that contain the input as a substring, then fall back to spell-check
    suggestions = all_ids.select { |id| id.include?(input) }
    suggestions += DidYouMean::SpellChecker.new(dictionary: all_ids).correct(input)
    suggestions = suggestions.uniq.first(3)

    lines = ["Unknown requirement '#{input}'"]
    lines << "Did you mean?\n#{suggestions.map { |s| "  #{s}" }.join("\n")}" unless suggestions.empty?
    abort lines.join("\n")
  end

  # Map output property names to requirement ID prefixes
  OUTPUT_PREFIXES = {
    'access_out' => '',
    'trigger_out' => ''
  }.freeze

  # Parse module edits from the transforms config, separating plain property values
  # from weight overrides. Array entries can be plain strings or single-key hashes:
  #   - plaintext          => plain value, normal weight
  #   - kerberos: highest  => plain value "kerberos" with weight override
  #
  # Returns { artisanal_count: Integer, weight_edits: Hash, edit_errors: Array, weight_errors: Array }
  def apply_module_edits(graph, module_edits)
    weight_edits = {}
    edit_errors = []
    weight_errors = []
    artisanal_count = 0

    module_edits.each do |module_name, modifications|
      additions = {}
      (modifications['add'] || {}).each do |property, values|
        next unless values.is_a?(Array)

        plain_values = []
        values.each do |entry|
          if entry.is_a?(Hash)
            entry.each do |value, level|
              plain_values << value.to_s

              prefix = OUTPUT_PREFIXES[property]
              if prefix.nil?
                weight_errors << "#{module_name}: weights are not supported on '#{property}' (only #{OUTPUT_PREFIXES.keys.join(', ')})"
                next
              end

              level_str = level.to_s.downcase
              unless Msf::Neo4j::Graph::WEIGHT_LEVELS.key?(level_str)
                weight_errors << "#{module_name}: unknown weight level '#{level}' for #{value} (expected: #{Msf::Neo4j::Graph::WEIGHT_LEVELS.keys.join(', ')})"
                next
              end

              req_id = "#{prefix}#{value}"
              weight_edits[module_name] ||= {}
              weight_edits[module_name][req_id] = Msf::Neo4j::Graph::WEIGHT_LEVELS[level_str]
            end
          else
            plain_values << entry.to_s
          end
        end
        additions[property] = plain_values
      end

      removals = modifications['remove'] || {}

      unless additions.empty? && removals.empty?
        begin
          graph.update_module_properties(
            module_name,
            additions: additions,
            removals: removals
          )
          artisanal_count += 1
          puts "  Updated: #{module_name}"
        rescue ArgumentError => e
          edit_errors << "#{module_name}: #{e.message}"
          elog "#{module_name}: #{e.message}"
        end
      end
    end

    { artisanal_count: artisanal_count, weight_edits: weight_edits, edit_errors: edit_errors, weight_errors: weight_errors }
  end

  desc "Find chains from unauthenticated modules to a target access type (e.g., TARGET=session/windows/meterpreter)"
  task :chains_to do
    target = ENV['TARGET']
    max_depth = (ENV['DEPTH'] || 4).to_i
    limit = (ENV['LIMIT'] || 50).to_i
    abort "Usage: rake module_graph:chains_to TARGET=session/windows/meterpreter [DEPTH=4] [LIMIT=50]" unless target

    with_graph do |graph|
      validate_requirement_id(graph, target, label: 'Access', match: :contains)
      results = graph.find_unauthenticated_chains_to(target, max_depth: max_depth, limit: limit)

      puts "\n" + "=" * 80
      puts "UNAUTHENTICATED CHAINS TO: #{target}"
      puts "=" * 80

      if results.empty?
        puts "No chains found (try increasing DEPTH)"
      else
        results.each_with_index do |chain, i|
          puts "\nChain #{i + 1} (#{chain[:chain_length]} modules):"
          chain[:chain].each_with_index do |mod, j|
            label = format_module(mod, chain[:target_names][j])
            pivot = chain[:access_pivots][j]
            if pivot
              puts "  #{label}  --[#{pivot}]-->"
            else
              puts "  #{label}"
            end
          end
        end
        puts "\n#{results.size} chains found"
      end
    end
  end

  desc "Find paths that transform one access type into another (e.g., FROM=authentication/hash/ntlm TO=authentication/kerberos)"
  task :transform_access do
    from = ENV['FROM']
    to = ENV['TO']
    max_depth = (ENV['DEPTH'] || 4).to_i
    limit = (ENV['LIMIT'] || 50).to_i
    abort "Usage: rake module_graph:transform_access FROM=authentication/hash/ntlm TO=authentication/kerberos [DEPTH=4] [LIMIT=50]" unless from && to

    with_graph do |graph|
      validate_requirement_id(graph, from, label: 'Access')
      validate_requirement_id(graph, to, label: 'Access')
      results = graph.find_access_escalation(from, to, max_depth: max_depth, limit: limit)

      puts "\n" + "=" * 80
      puts "ACCESS TRANSFORM: #{from} -> #{to}"
      puts "=" * 80

      if results.empty?
        puts "No paths found (try increasing DEPTH)"
      else
        results.each_with_index do |chain, i|
          weight_label = chain[:total_weight] != 0 ? " | weight: #{chain[:total_weight]}" : ""
          puts "\nPath #{i + 1} (#{chain[:chain_length]} modules#{weight_label}):"
          chain[:chain].each_with_index do |mod, j|
            label = format_module(mod, chain[:target_names][j])
            pivot = chain[:access_pivots][j]
            if pivot
              puts "  #{label}  --[#{pivot}]-->"
            else
              puts "  #{label}"
            end
          end
        end
        puts "\n#{results.size} paths found"
      end
    end
  end

  desc "Find paths from an access type to run a specific module (e.g., FROM=authentication/hash/ntlm MODULE=post/windows/gather/hashdump)"
  task :reach_module do
    from = ENV['FROM']
    target_module = ENV['MODULE']
    max_depth = (ENV['DEPTH'] || 4).to_i
    limit = (ENV['LIMIT'] || 50).to_i
    abort "Usage: rake module_graph:reach_module FROM=authentication/hash/ntlm MODULE=post/windows/gather/hashdump [DEPTH=4] [LIMIT=50]" unless from && target_module

    with_graph do |graph|
      validate_requirement_id(graph, from, label: 'Access')
      result = graph.find_paths_to_module(from, target_module, max_depth: max_depth, limit: limit)

      puts "\n" + "=" * 80
      puts "PATHS TO MODULE: #{target_module}"
      puts "STARTING FROM:   #{from}"
      puts "=" * 80

      if result[:target_requirements].any?
        puts "\nTarget module requires: #{result[:target_requirements].join(', ')}"
      end

      if result[:paths].empty?
        puts "\nNo paths found (try increasing DEPTH)"
      else
        result[:paths].each_with_index do |path, i|
          weight_label = path[:total_weight] != 0 ? " | weight: #{path[:total_weight]}" : ""
          puts "\nPath #{i + 1} (#{path[:chain_length]} intermediate modules#{weight_label}):"
          path[:chain].each_with_index do |mod, j|
            label = format_module(mod, path[:target_names][j])
            req = path[:requirements_used][j]
            if req
              puts "  #{label}  --[#{req}]-->"
            else
              puts "  #{label}"
            end
          end
          puts "  #{target_module}  (target)"
        end
        puts "\n#{result[:paths].size} paths found"
      end
    end
  end

  desc "Find what credentials/sessions a trigger type yields (e.g., TRIGGER=coercion/smb)"
  task :coercion_chains do
    coercion = ENV['TRIGGER'] || 'coercion/smb'

    with_graph do |graph|
      validate_requirement_id(graph, coercion, label: 'Trigger')
      results = graph.find_coercion_chains(coercion)

      puts "\n" + "=" * 80
      puts "TRIGGER CHAINS FROM: #{coercion}"
      puts "=" * 80

      if results.empty?
        puts "No modules consume this trigger type"
      else
        results.each do |entry|
          label = format_module(entry[:module_id], entry[:target_name])
          puts "\n  #{label} (#{entry[:module_type]})"
          entry[:produces_access].each do |access|
            puts "    -> #{access}"
          end
        end
        puts "\n#{results.size} modules found"
      end
    end
  end

  desc "Find full attack paths (coercion/exploit -> post) [PLATFORM=windows] [DEPTH=6] [LIMIT=25]"
  task :full_paths do
    platform = ENV['PLATFORM']
    max_depth = (ENV['DEPTH'] || 6).to_i
    limit = (ENV['LIMIT'] || 25).to_i

    with_graph do |graph|
      results = graph.find_full_attack_paths(max_depth: max_depth, platform: platform, limit: limit)

      puts "\n" + "=" * 80
      puts "FULL ATTACK PATHS#{platform ? " (platform: #{platform})" : ''}"
      puts "=" * 80

      if results.empty?
        puts "No paths found (try increasing DEPTH or removing PLATFORM filter)"
      else
        results.each_with_index do |path, i|
          puts "\nPath #{i + 1} (#{path[:chain_length]} modules):"
          path[:chain].each_with_index do |mod, j|
            label = format_module(mod, path[:target_names][j])
            type = path[:module_types][j]
            req = path[:requirements_used][j]
            prefix = "  [#{type}]".ljust(14)
            if req
              puts "#{prefix} #{label}  --[#{req}]-->"
            else
              puts "#{prefix} #{label}"
            end
          end
        end
        puts "\n#{results.size} paths found"
      end
    end
  end

  desc "Find all modules reachable from an access type (e.g., ACCESS=authentication/hash/ntlm) [DEPTH=3] [LIMIT=50]"
  task :reachable do
    access = ENV['ACCESS']
    max_depth = (ENV['DEPTH'] || 3).to_i
    limit = (ENV['LIMIT'] || 50).to_i
    abort "Usage: rake module_graph:reachable ACCESS=authentication/hash/ntlm [DEPTH=3] [LIMIT=50]" unless access

    with_graph do |graph|
      validate_requirement_id(graph, access, label: 'Access')
      results = graph.find_reachable_from(access, max_depth: max_depth, limit: limit)

      puts "\n" + "=" * 80
      puts "MODULES REACHABLE FROM: #{access}"
      puts "=" * 80

      if results.empty?
        puts "No modules reachable from this access type"
      else
        current_distance = nil
        results.each do |entry|
          if entry[:distance] != current_distance
            current_distance = entry[:distance]
            puts "\n  --- Distance #{current_distance} ---"
          end
          label = format_module(entry[:module_id], entry[:target_name])
          produces = entry[:produces].empty? ? '' : "  -> #{entry[:produces].join(', ')}"
          puts "  [#{entry[:module_type]}] #{label}#{produces}"
        end
        puts "\n#{results.size} modules reachable"
      end
    end
  end
end

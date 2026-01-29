require 'msfenv'

require 'rex'
require 'msf/core/constants'
require Rails.root.join('app/models/application_record')
require Rails.root.join('app/validators/metasploit/framework/executable_path_validator')
require Rails.root.join('app/validators/metasploit/framework/file_path_validator')

require_relative '../msf/neo4j'

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
  result = Set.new
  mod_ins.platform.names.each do |platform|
    platform_str = platform.to_s.downcase
    if PLATFORM_MAPPING.key?(platform_str)
      # Platform maps to multiple platforms (e.g., java -> windows, linux, osx)
      result.merge(PLATFORM_MAPPING[platform_str])
    else
      # Keep the original platform
      result.add(platform_str)
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
        # fixme: this is gonna get fooled by modules that need PASSWORD set for the creation of an accountI'd
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

# todo: this is going to be horrifically slow, we're initializing every payload exploit permutation that is compatible
def session_out_property(mod_ins)
  result = Set.new

  unless ENV['NEED_SPEED'].nil? # mock this data while testing to speed things way up
    return %w[
      windows/meterpreter
      linux/meterpreter
    ]
  end

  loop do
    mod_ins.compatible_payloads.each do |ref_name, klass|
      payload_mod_ins = klass.new
      next unless payload_mod_ins.session
      next unless payload_mod_ins.platform

      result.merge(payload_mod_ins.platform.names.reject(&:empty?).map(&:downcase).product([payload_mod_ins.session.type]).map { _1.join('/') })
    end

    break if mod_ins.target == mod_ins.targets.last

    mod_ins.datastore['TARGET'] = mod_ins.datastore['TARGET'].to_i + 1
  end

  result.empty? ? nil : result.to_a
end

NEO4J_PASSWORD = ENV['NEO4J_PASSWORD'] || 'neo4j'

PROTOCOL_SESSIONS = %w[ ldap mssql mysql postgresql smb ]
# Load Neo4j transforms configuration
TRANSFORMS_FILE = Rails.root.join('data/neo4j_transforms.yml')
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
    # Module missing data:
    # exploit:
    #   session types they can open
    mod_ins = mod_cls.new

    properties = {
      type: mod_cls.type
    }

    case mod_cls.type
    when ::Msf::MODULE_AUX
      properties[:authentication_in] = authentication_in_property(mod_ins)
    when ::Msf::MODULE_EXPLOIT
      properties[:authentication_in] = authentication_in_property(mod_ins)
      properties[:platform] = platform_property(mod_ins)
      properties[:session_in] = session_in_property(mod_ins)
      # todo: this should be updated to be more accurately reflect the types of sessions a module can open
      #properties[:session_out] = properties[:platform].product(%w[ shell meterpreter ]).map { _1.join('/') }
      properties[:session_out] = session_out_property(mod_ins)
    when ::Msf::MODULE_POST
      properties[:platform] = platform_property(mod_ins)
      properties[:session_in] = session_in_property(mod_ins)
    end

    graph.create_module(
      mod_cls.fullname,
      **properties
    )
  end
end

namespace :module_graph do
  desc "Delete all data from Neo4j database"
  task :clean do
    puts "Clearing Neo4j database..."
    graph = Msf::Neo4j::Graph.new(password: NEO4J_PASSWORD)
    graph.clear_database
    graph.close
    puts "Done!"
  end

  desc "Populate module graph with your application data"
  task :populate do
    puts "Populating module graph..."
    graph = Msf::Neo4j::Graph.new(password: NEO4J_PASSWORD)

    begin
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
        rescue Exception => e
          $stderr.puts "Failed to import #{mod_cls.fullname}"
          $stderr.puts "#{e.class}: #{e.message}".indent(2)
          $stderr.puts e.backtrace.join("\n").indent(2)
        else
          modules_imported += 1
        end
      end
      puts "Phase 1: Completed importing #{modules_imported} modules.\n"

      # Phase 2: Apply artisanal properties from transforms file
      puts "Phase 2: Applying module edits..."
      module_edits = TRANSFORMS_CONFIG['module_edits'] || {}

      if module_edits.any?
        artisanal_count = 0
        errors = []

        module_edits.each do |module_name, modifications|
          additions = modifications['add'] || {}
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
              errors << "#{module_name}: #{e.message}"
              $stderr.puts "  ERROR - #{module_name}: #{e.message}"
            end
          end
        end

        puts "Phase 2: Applied module edits to #{artisanal_count} modules."
        unless errors.empty?
          puts "\nErrors encountered:"
          errors.each { |error| puts "  - #{error}" }
          raise "Module edits validation failed. Fix the errors above in #{TRANSFORMS_FILE}"
        end
      else
        puts "No module edits found in #{TRANSFORMS_FILE}"
      end
      puts "Phase 2: Completed.\n"

      puts "Population complete!"
      puts "View at http://localhost:7474"
    ensure
      graph.close
    end
  end

  desc "Show module graph statistics"
  task :stats do
    puts "Fetching statistics..."
    graph = Msf::Neo4j::Graph.new(password: NEO4J_PASSWORD)

    begin
      stats = graph.get_hypergraph_stats

      puts "\n" + "=" * 60
      puts "MODULE GRAPH STATISTICS"
      puts "=" * 60

      if stats.empty?
        puts "No data in module graph"
      else
        stats.each do |key, value|
          formatted_value = value.is_a?(Float) ? format('%.2f', value) : value
          puts "#{key}: #{formatted_value}"
        end
      end
      
      puts "=" * 60

    ensure
      graph.close
    end
  end

  desc "Build authentication and session flow relationships (direct module-to-module)"
  task :build_relationships do
    puts "Building relationships..."
    graph = Msf::Neo4j::Graph.new(password: NEO4J_PASSWORD)

    begin
      graph.create_all_relationships
      puts "Done!"
    ensure
      graph.close
    end
  end

  desc "Build requirement node model with typed nodes (Access, Trigger)"
  task :build_requirement_model do
    puts "Building requirement model..."
    graph = Msf::Neo4j::Graph.new(password: NEO4J_PASSWORD)

    begin
      graph.build_requirement_model
      puts "Done!"
    ensure
      graph.close
    end
  end

  desc "Clear requirement nodes and their relationships (preserves Module nodes)"
  task :clear_requirement_model do
    puts "Clearing requirement model..."
    graph = Msf::Neo4j::Graph.new(password: NEO4J_PASSWORD)

    begin
      graph.clear_requirement_model
      puts "Done!"
    ensure
      graph.close
    end
  end

  desc "Show requirement model statistics"
  task :requirement_stats do
    puts "Fetching requirement model statistics..."
    graph = Msf::Neo4j::Graph.new(password: NEO4J_PASSWORD)

    begin
      stats = graph.get_requirement_stats

      puts "\n" + "=" * 60
      puts "REQUIREMENT MODEL STATISTICS"
      puts "=" * 60

      if stats.empty?
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
    ensure
      graph.close
    end
  end

  desc "Reset module graph (clear + populate)"
  task :reset => [:clean, :populate]

  desc "Reset module graph and build requirement model"
  task :reset_with_requirements => [:reset, :build_requirement_model]

  desc "List all requirement nodes in a table format to help spot typos and modeling errors"
  task :list_requirements do
    puts "Fetching requirement nodes..."
    graph = Msf::Neo4j::Graph.new(password: NEO4J_PASSWORD)

    begin
      requirements = []
      graph.instance_eval do
        session do |sess|
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
            binding.pry if ((record['type'] || 'Unknown') == 'Unknown')
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
        puts "No requirement nodes found. Run 'rake module_graph:build_requirement_model' first."
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
    ensure
      graph.close
    end
  end

  # =========================================================================
  # ATTACK CHAIN QUERIES
  # =========================================================================

  desc "Find chains from unauthenticated modules to a target access type (e.g., TARGET=session/windows/meterpreter)"
  task :chains_to do
    target = ENV['TARGET']
    max_depth = (ENV['DEPTH'] || 4).to_i
    limit = (ENV['LIMIT'] || 50).to_i
    abort "Usage: rake module_graph:chains_to TARGET=session/windows/meterpreter [DEPTH=4] [LIMIT=50]" unless target

    graph = Msf::Neo4j::Graph.new(password: NEO4J_PASSWORD)
    begin
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
            pivot = chain[:access_pivots][j]
            if pivot
              puts "  #{mod}  --[#{pivot}]-->"
            else
              puts "  #{mod}"
            end
          end
        end
        puts "\n#{results.size} chains found"
      end
    ensure
      graph.close
    end
  end

  desc "Find credential/access escalation paths (e.g., FROM=authentication/hash/ntlm TO=authentication/kerberos)"
  task :escalate do
    from = ENV['FROM']
    to = ENV['TO']
    max_depth = (ENV['DEPTH'] || 4).to_i
    limit = (ENV['LIMIT'] || 50).to_i
    abort "Usage: rake module_graph:escalate FROM=authentication/hash/ntlm TO=authentication/kerberos [DEPTH=4] [LIMIT=50]" unless from && to

    graph = Msf::Neo4j::Graph.new(password: NEO4J_PASSWORD)
    begin
      results = graph.find_access_escalation(from, to, max_depth: max_depth, limit: limit)

      puts "\n" + "=" * 80
      puts "ACCESS ESCALATION: #{from} -> #{to}"
      puts "=" * 80

      if results.empty?
        puts "No escalation paths found (try increasing DEPTH)"
      else
        results.each_with_index do |chain, i|
          puts "\nPath #{i + 1} (#{chain[:chain_length]} modules):"
          chain[:chain].each_with_index do |mod, j|
            pivot = chain[:access_pivots][j]
            if pivot
              puts "  #{mod}  --[#{pivot}]-->"
            else
              puts "  #{mod}"
            end
          end
        end
        puts "\n#{results.size} paths found"
      end
    ensure
      graph.close
    end
  end

  desc "Find what credentials/sessions a coercion type yields (e.g., COERCION=coercion/smb)"
  task :coercion_chains do
    coercion = ENV['COERCION'] || 'coercion/smb'

    graph = Msf::Neo4j::Graph.new(password: NEO4J_PASSWORD)
    begin
      results = graph.find_coercion_chains(coercion)

      puts "\n" + "=" * 80
      puts "COERCION CHAINS FROM: #{coercion}"
      puts "=" * 80

      if results.empty?
        puts "No modules consume this coercion type"
      else
        results.each do |entry|
          puts "\n  #{entry[:module_id]} (#{entry[:module_type]})"
          entry[:produces_access].each do |access|
            puts "    -> #{access}"
          end
        end
        puts "\n#{results.size} modules found"
      end
    ensure
      graph.close
    end
  end

  desc "Find full attack paths (coercion/exploit -> post) [PLATFORM=windows] [DEPTH=6] [LIMIT=25]"
  task :full_paths do
    platform = ENV['PLATFORM']
    max_depth = (ENV['DEPTH'] || 6).to_i
    limit = (ENV['LIMIT'] || 25).to_i

    graph = Msf::Neo4j::Graph.new(password: NEO4J_PASSWORD)
    begin
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
            type = path[:module_types][j]
            req = path[:requirements_used][j]
            prefix = "  [#{type}]".ljust(14)
            if req
              puts "#{prefix} #{mod}  --[#{req}]-->"
            else
              puts "#{prefix} #{mod}"
            end
          end
        end
        puts "\n#{results.size} paths found"
      end
    ensure
      graph.close
    end
  end

  desc "Find all modules reachable from an access type (e.g., ACCESS=authentication/hash/ntlm) [DEPTH=3] [LIMIT=50]"
  task :reachable do
    access = ENV['ACCESS']
    max_depth = (ENV['DEPTH'] || 3).to_i
    limit = (ENV['LIMIT'] || 50).to_i
    abort "Usage: rake module_graph:reachable ACCESS=authentication/hash/ntlm [DEPTH=3] [LIMIT=50]" unless access

    graph = Msf::Neo4j::Graph.new(password: NEO4J_PASSWORD)
    begin
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
          produces = entry[:produces].empty? ? '' : "  -> #{entry[:produces].join(', ')}"
          puts "  [#{entry[:module_type]}] #{entry[:module_id]}#{produces}"
        end
        puts "\n#{results.size} modules reachable"
      end
    ensure
      graph.close
    end
  end
end

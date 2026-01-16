require 'msfenv'

require 'rex'
require 'msf/core/constants'
require Rails.root.join('app/models/application_record.rb')

require_relative '../hypergraph_neo4j'

def load_platform_mappings(transforms)
  result = {}
  mappings = transforms.fetch('platform_edits', {})
  mappings.each_pair do |k, v|
    result[Msf::Platform.find_platform(k).realname] = v.map { Msf::Platform.find_platform(_1).realname }
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

  result.delete('Unknown')
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
  end

  # check if we can be authenticated by a session
  session_auth = (session_type_in_property(mod_ins) || []) & PROTOCOL_SESSIONS
  unless session_auth.empty?
    result.merge(session_auth.map { "session/#{_1}" })
  end

  result.delete('auto')
  result.empty? ? nil : result.to_a
end

def session_type_in_property(mod_ins)
  result = Set.new

  result.merge(mod_ins.session_types) if mod_ins.is_a?(Msf::Exploit::Local)

  result.add('ldap') if mod_ins.is_a?(Msf::OptionalSession::LDAP)
  result.add('mssql') if mod_ins.is_a?(Msf::OptionalSession::MSSQL)
  result.add('mysql') if mod_ins.is_a?(Msf::OptionalSession::MySQL)
  result.add('postgresql') if mod_ins.is_a?(Msf::OptionalSession::PostgreSQL)
  result.add('smb') if mod_ins.is_a?(Msf::OptionalSession::SMB)

  result.empty? ? nil : result.to_a
end

NEO4J_PASSWORD = ENV['NEO4J_PASSWORD'] || 'neo4j'

PROTOCOL_SESSIONS = %w[ ldap mssql mysql postgresql smb ]
# Load Neo4j transforms configuration
TRANSFORMS_FILE = Rails.root.join('data/neo4j_transforms.yml')
TRANSFORMS_CONFIG = File.exist?(TRANSFORMS_FILE) ? YAML.load_file(TRANSFORMS_FILE) : {}
PLATFORM_MAPPING = load_platform_mappings(TRANSFORMS_CONFIG)

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
    properties[:session_type_in] = session_type_in_property(mod_ins)
    # todo: this should be updated to be more accurately reflect the types of sessions a module can open
    properties[:session_type_out] = %w[ shell meterpreter ]
  when ::Msf::MODULE_POST
    properties[:platform] = platform_property(mod_ins)
    properties[:session_type_in] = mod_ins.session_types
  end

  graph.create_node(
    mod_cls.fullname,
    **properties
  )
rescue Exception => e
  $stderr.puts "Failed to import #{mod_cls.fullname}"
  $stderr.puts "#{e.class}: #{e.message}".indent(2)
  $stderr.puts e.backtrace.join("\n").indent(2)
end

namespace :hypergraph do
  desc "Delete all data from Neo4j database"
  task :clean do
    puts "Clearing Neo4j database..."
    graph = HypergraphNeo4j::Graph.new(password: NEO4J_PASSWORD)
    graph.clear_database
    graph.close
    puts "Done!"
  end

  desc "Populate hypergraph with your application data"
  task :populate do
    puts "Populating hypergraph..."
    graph = HypergraphNeo4j::Graph.new(password: NEO4J_PASSWORD)

    begin
      puts "Phase 1: Importing modules..."
      create_opts = {}
      create_opts[:module_types] = [
        ::Msf::MODULE_AUX, ::Msf::MODULE_EXPLOIT, ::Msf::MODULE_POST
      ]

      framework = ::Msf::Simple::Framework.create(create_opts)

      modules_imported = 0
      framework.modules.each do |name, mod|
        if mod.nil?
          puts "  No module object for: #{name}"
          next
        end
        import_module(graph, mod)
        modules_imported += 1
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
              graph.update_node_properties(
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

  desc "Show hypergraph statistics"
  task :stats do
    puts "Fetching statistics..."
    graph = HypergraphNeo4j::Graph.new(password: NEO4J_PASSWORD)

    begin
      stats = graph.get_hypergraph_stats

      puts "\n" + "=" * 60
      puts "HYPERGRAPH STATISTICS"
      puts "=" * 60
      
      if stats.empty?
        puts "No data in hypergraph"
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

  desc "Reset hypergraph (clear + populate)"
  task :reset => [:clean, :populate]
end
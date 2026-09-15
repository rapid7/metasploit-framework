# frozen_string_literal: true

require 'erb'
require 'fileutils'
require 'rex/arch'

# Helpers namespaced to avoid polluting top-level scope
module MsfModuleGenerator
  # Infer platform from path prefix
  def self.infer_platform(path)
    prefix = path.split('/').first.downcase

    case prefix
    when 'windows', 'win'
      'win'
    when 'linux'
      'linux'
    when 'osx'
      'osx'
    when 'apple_ios'
      'apple_ios'
    when 'unix'
      'unix'
    when 'multi'
      # multi/ modules target multiple platforms -- can't pick one, leave for developer
      nil
    end
  end

  # Infer architecture from path context
  def self.infer_arch(path, type)
    # For encoders and nops, the first path segment IS the architecture
    if %w[encoder nop].include?(type)
      return path.split('/').first.downcase
    end

    # For payloads, the second path segment is often the architecture
    if type == 'payload_single'
      segments = path.split('/')
      if segments.length >= 2
        second = segments[1].downcase
        return second if known_arch?(second)
      end
      # Single-segment arch payloads: the first segment IS the arch
      first = segments.first.downcase
      return first if %w[cmd java php python ruby].include?(first)
    end

    # For other types, arch cannot be reliably inferred from the path --
    # leave it to the developer (deliberately not guessing from platform)
    nil
  end

  # The complete set of architecture names the generator will accept. Derived from the
  # authoritative Rex::Arch::ARCH_TYPES (so it cannot drift from the framework as new
  # arches land) plus 'generic', which is not an ARCH_TYPES member but is a real module
  # path prefix (modules/encoders/generic, modules/payloads/singles/generic) that maps to
  # ARCH_ALL. ARCH_ANY ('_any_') is intentionally excluded -- it is a matcher sentinel, not
  # an arch a module is scaffolded for.
  KNOWN_ARCHES = (Rex::Arch::ARCH_TYPES + %w[generic]).freeze

  # Check if a string matches a known architecture name
  def self.known_arch?(name)
    KNOWN_ARCHES.include?(name)
  end

  # Map user-provided arch string to framework constant name.
  # Known archs (see known_arch?, derived from Rex::Arch::ARCH_TYPES) map to ARCH_<UPCASE>,
  # which is the framework's naming rule for every arch constant (every ARCH_TYPES member
  # has a matching ARCH_<UPCASE>). Exceptions to the <UPCASE> rule are mapped explicitly in
  # ARCH_CONST_OVERRIDES (e.g. 'generic' -> ARCH_ALL, since ARCH_GENERIC does not exist). An
  # UNKNOWN arch returns nil rather than manufacturing an invalid ARCH_* constant: nil flows
  # through the generator's existing fail-loud path (the template emits 'Arch' => nil/[nil],
  # which fails module load with a clear message), so there is a single fail-loud mechanism,
  # not two.

  # Known archs whose constant name is NOT ARCH_<UPCASE>. Keep in sync with lib/rex/arch.rb.
  ARCH_CONST_OVERRIDES = {
    'generic' => 'ARCH_ALL' # the generic/ tree (encoders, payloads) uses ARCH_ALL; ARCH_GENERIC does not exist
  }.freeze

  def self.map_arch_const(arch)
    return nil if arch.nil?

    normalized = arch.downcase
    return nil unless known_arch?(normalized)

    ARCH_CONST_OVERRIDES.fetch(normalized) { "ARCH_#{normalized.upcase}" }
  end

  # Map platform string to the canonical metadata form expected by each module type
  def self.map_platform_meta(platform, type)
    return nil if platform.nil?

    case type
    when 'post'
      # Post modules use full platform names in arrays
      case platform
      when 'win' then 'windows'
      when 'osx' then 'osx'
      else platform
      end
    else
      # Exploits/payloads use short form
      platform
    end
  end

  # Render a value as a valid Ruby string literal for interpolation into a template.
  # Prefers a single-quoted literal (the framework's Style/StringLiterals convention)
  # and only falls back to an escaped double-quoted literal (via inspect) when the
  # value contains a single quote or backslash -- so an ordinary author like
  # "Jane Tester" stays single-quoted and rubocop-clean, while "O'Connor" is escaped
  # instead of producing the syntactically broken 'O'Connor'.
  def self.ruby_str(value)
    str = value.to_s
    return "'#{str}'" unless str.include?("'") || str.include?('\\')

    str.inspect
  end
end

namespace :msf do
  desc 'List available module types for the generator'
  task :'generate:types' do
    puts 'Available module types:'
    puts '  exploit         - Remote/local exploit module'
    puts '  auxiliary       - Scanner, fuzzer, or information-gathering module'
    puts '  post            - Post-exploitation module (runs on a session)'
    puts '  payload_single  - Single-stage payload'
    puts '  encoder         - Payload encoder'
    puts '  nop             - NOP sled generator'
    puts '  evasion         - Evasion module'
    puts ''
    puts 'Usage: bundle exec rake \'msf:generate[TYPE,PATH,PLATFORM,ARCH]\''
    puts ''
    puts 'Examples:'
    puts '  bundle exec rake \'msf:generate[exploit,linux/http/my_vuln]\''
    puts '  bundle exec rake \'msf:generate[auxiliary,scanner/http/my_scanner]\''
    puts '  bundle exec rake \'msf:generate[post,windows/gather/my_gatherer]\''
    puts '  bundle exec rake \'msf:generate[exploit,windows/http/my_vuln,win,x64]\''
    puts ''
    puts 'Environment variables:'
    puts '  MSF_MOD_AUTHOR  - Author name (defaults to git user.name)'
    puts '  MSF_MOD_CVE     - CVE identifier (e.g., 2024-12345)'
    puts '  MSF_DRY_RUN=1   - Preview what would be generated without writing files'
  end

  desc 'Generate a new Metasploit module with correct structure and documentation'
  task :generate, [:type, :path, :platform, :arch] do |_t, args|
    type = args[:type]
    path = args[:path]
    platform = args[:platform]
    arch = args[:arch]

    valid_types = %w[exploit auxiliary post payload_single encoder nop evasion]
    unless valid_types.include?(type)
      abort "Error: Invalid type '#{type}'. Must be one of: #{valid_types.join(', ')}\n" \
            "Hint: Use 'payload_single' for single-stage payloads (not 'payload').\n" \
            "Run 'bundle exec rake msf:generate:types' to see descriptions and examples."
    end

    unless path && !path.empty?
      abort 'Error: path is required (e.g., linux/http/my_exploit)'
    end

    # Reject absolute paths and traversal/empty segments before the path is
    # interpolated into File.join/File.write destinations -- otherwise a path like
    # '../../outside' or '/etc/foo' would create or overwrite files outside the
    # modules/ and documentation/ trees.
    if path.start_with?('/') || path.include?('\\')
      abort "Error: path must be relative (e.g., linux/http/my_exploit), not absolute: '#{path}'"
    end
    if path.split('/').any? { |seg| seg.empty? || seg == '.' || seg == '..' }
      abort "Error: path must not contain empty, '.', or '..' segments: '#{path}'"
    end

    dry_run = ENV['MSF_DRY_RUN'] == '1'

    # Infer platform from path prefix when not explicitly provided
    platform ||= MsfModuleGenerator.infer_platform(path)

    # Infer arch from path convention when not explicitly provided
    arch ||= MsfModuleGenerator.infer_arch(path, type)

    # Map type to the physical source directory under modules/ (plural, matches the
    # on-disk layout: modules/exploits, modules/payloads/singles, ...).
    mod_dir = case type
              when 'payload_single' then 'payloads/singles'
              when 'auxiliary' then 'auxiliary'
              when 'post' then 'post'
              when 'evasion' then 'evasion'
              else "#{type}s"
              end

    # Map type to its SINGULAR form, used for BOTH the documentation directory
    # (documentation/modules/exploit, .../payload/singles) and the msfconsole fullname
    # in `use ...` commands (exploit/..., payload/...). Both are singular and identical,
    # distinct from the plural source dir above, so mod_dir cannot be reused for them.
    singular_dir = case type
                   when 'payload_single' then 'payload/singles'
                   when 'auxiliary' then 'auxiliary'
                   when 'post' then 'post'
                   when 'evasion' then 'evasion'
                   else type # exploit, encoder, nop
                   end

    module_file = File.join('modules', mod_dir, "#{path}.rb")
    doc_file = File.join('documentation', 'modules', singular_dir, "#{path}.md")

    # Full module name as msfconsole would load it (used in the generated doc's
    # `use ...` verification steps).
    console_name = File.join(singular_dir, path)

    # Collision check covers BOTH destinations: a doc file can pre-exist independently
    # of its module file, and writing it unconditionally would silently destroy a
    # hand-written document.
    existing = [module_file, doc_file].select { |f| File.exist?(f) }
    if dry_run
      existing.each do |f|
        puts "Note: #{f} already exists (would not overwrite in real run)"
      end
    elsif existing.any?
      abort "Error: #{existing.join(', ')} already exist(s). Use a different path or remove the existing file(s)."
    end

    # Template variables
    author = ENV['MSF_MOD_AUTHOR'] || `git config user.name`.strip
    author = 'Your Name' if author.empty?
    cve = ENV['MSF_MOD_CVE']
    date = Time.now.strftime('%Y-%m-%d')
    mod_name = path.split('/').last.split('_').map(&:capitalize).join(' ')

    # Arch constant mapping
    arch_const = MsfModuleGenerator.map_arch_const(arch)

    # Platform string for metadata (canonical form)
    platform_meta = MsfModuleGenerator.map_platform_meta(platform, type)

    # Select template
    template_name = "#{type}.rb.erb"
    template_path = File.join(File.dirname(__FILE__), 'templates', template_name)
    unless File.exist?(template_path)
      abort "Error: Template not found at #{template_path}"
    end

    # Render module template
    template = ERB.new(File.read(template_path), trim_mode: '-')
    binding_context = binding
    module_content = template.result(binding_context)

    # Render documentation template
    doc_template_path = File.join(File.dirname(__FILE__), 'templates', 'module_doc.md.erb')
    doc_content = if File.exist?(doc_template_path)
                    doc_template = ERB.new(File.read(doc_template_path), trim_mode: '-')
                    doc_template.result(binding_context)
                  end

    # Collect fail-loud placeholders that were emitted so we can warn about them at
    # generation time -- these will fail module load or trip msftidy until resolved,
    # matching the generator's force-correctness principle (no plausible-but-wrong guesses).
    #
    # NOTE: these lists mirror which fields each template actually emits as fail-loud
    # placeholders -- keep them in sync when adding/removing a Platform/Arch/Rank field
    # in the corresponding *.rb.erb template.
    load_blockers = []
    types_with_platform = %w[exploit evasion payload_single post]
    types_with_arch = %w[exploit evasion payload_single encoder nop]
    types_with_rank = %w[exploit]
    if types_with_platform.include?(type) && platform.nil?
      load_blockers << 'Platform (emitted as nil/[nil]) -- the module will not load until you set a real platform'
    end
    if types_with_arch.include?(type) && arch_const.nil?
      load_blockers << 'Arch (emitted as nil/[nil]) -- the module will not load until you set a real architecture'
    end
    if types_with_rank.include?(type)
      load_blockers << 'Rank (no explicit Rank emitted) -- msftidy flags this (INFO) until you set one (ManualRanking to ExcellentRanking)'
    end

    print_generation_warning = lambda do
      break if load_blockers.empty?

      puts ''
      puts '⚠ This module is intentionally incomplete and will not load / pass tooling until you resolve:'
      load_blockers.each { |b| puts "    - #{b}" }
    end

    if dry_run
      puts "=== DRY RUN === (set MSF_DRY_RUN=0 or unset to write files)\n\n"
      puts "Would create: #{module_file}"
      puts '-' * 60
      puts module_content
      puts '-' * 60
      if doc_content
        puts "\nWould create: #{doc_file}"
        puts '-' * 60
        puts doc_content
        puts '-' * 60
      end
      print_generation_warning.call
    else
      # Write module file
      FileUtils.mkdir_p(File.dirname(module_file))
      File.write(module_file, module_content)
      puts "Created: #{module_file}"

      # Write documentation file
      if doc_content
        FileUtils.mkdir_p(File.dirname(doc_file))
        File.write(doc_file, doc_content)
        puts "Created: #{doc_file}"
      end

      # Syntax check. argv-form system (no shell) so a path with shell metacharacters
      # cannot execute anything, and the exit status is surfaced rather than ignored --
      # a template that renders invalid Ruby must not report success.
      puts "\nVerifying syntax..."
      unless system('ruby', '-c', module_file)
        puts "⚠ Syntax check failed for #{module_file} -- the generated file is not valid Ruby. " \
             'This is a generator bug; please report it.'
      end

      print_generation_warning.call

      # Post-generation guidance
      puts ''
      puts 'Next steps:'
      puts "  1. Fill in all TODO and PLACEHOLDER markers in #{module_file}"
      puts '     (the module will NOT load until every PLACEHOLDER value is replaced with a real one)'
      puts "  2. Run: ruby tools/dev/msftidy.rb #{module_file}"
      puts "  3. Run: bundle exec rubocop #{module_file}"
      puts "  4. Fill in the Scenarios section of #{doc_file} with real testing output"
      puts "  5. Run: ruby tools/dev/msftidy_docs.rb #{doc_file}"
      puts '  6. Test the module against a real target to confirm it works as intended'
    end
  end
end

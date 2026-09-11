# frozen_string_literal: true

require 'erb'
require 'fileutils'

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
    when 'osx', 'apple_ios'
      'osx'
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

  # Check if a string matches a known architecture name
  def self.known_arch?(name)
    %w[
      x86 x64 cmd php ppc sparc mipsbe mipsle mips64 armle armbe aarch64
      riscv32le riscv64le loongarch64 ruby generic tty python java
    ].include?(name)
  end

  # Map user-provided arch string to framework constant name.
  # Known archs (see known_arch?) map to ARCH_<UPCASE>, which is the framework's
  # naming rule for every arch constant (verified against lib/rex/arch.rb and real
  # modules). An UNKNOWN arch returns nil rather than manufacturing an invalid
  # ARCH_* constant: nil flows through the generator's existing fail-loud path
  # (the template emits 'Arch' => nil/[nil], which fails module load with a clear
  # message), so there is a single fail-loud mechanism, not two. Adding a brand-new
  # arch requires adding it to known_arch? first -- an accepted limitation, since
  # new arches are rare and not something a newcomer scaffolds.
  def self.map_arch_const(arch)
    return nil if arch.nil?

    normalized = arch.downcase
    return nil unless known_arch?(normalized)

    "ARCH_#{normalized.upcase}"
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

    dry_run = ENV['MSF_DRY_RUN'] == '1'

    # Infer platform from path prefix when not explicitly provided
    platform ||= MsfModuleGenerator.infer_platform(path)

    # Infer arch from path convention when not explicitly provided
    arch ||= MsfModuleGenerator.infer_arch(path, type)

    # Map type to module directory
    mod_dir = case type
              when 'payload_single' then 'payloads/singles'
              when 'auxiliary' then 'auxiliary'
              when 'post' then 'post'
              when 'evasion' then 'evasion'
              else "#{type}s"
              end

    module_file = File.join('modules', mod_dir, "#{path}.rb")
    doc_file = File.join('documentation', 'modules', mod_dir, "#{path}.md")

    if dry_run
      if File.exist?(module_file)
        puts "Note: #{module_file} already exists (would not overwrite in real run)"
      end
    elsif File.exist?(module_file)
      abort "Error: #{module_file} already exists. Use a different path or remove the existing file."
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
    types_with_platform = %w[exploit evasion payload_single]
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

      # Syntax check
      puts "\nVerifying syntax..."
      system("ruby -c #{module_file}")

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

# frozen_string_literal: true
require 'rubygems'
require 'rubygems/user_interaction'
require 'fileutils'

##
# Gem::YARDoc provides methods to generate YARDoc and yri data for installed gems
# upon gem installation.
#
# This file is automatically required by RubyGems 1.9 and newer.

module YARD
  class RubygemsHook
    include Gem::UserInteraction
    extend Gem::UserInteraction

    @yard_version = nil

    ##
    # Force installation of documentation?

    attr_accessor :force

    ##
    # Generate yard?

    attr_accessor :generate_yard

    ##
    # Generate yri data?

    attr_accessor :generate_yri

    class << self
      ##
      # Loaded version of YARD. Set by ::load_yard

      attr_reader :yard_version
    end

    ##
    # Post installs hook that generates documentation for each specification in
    # +specs+

    def self.generation_hook(installer, specs)
      start = Time.now
      types = installer.document

      generate_yard = types.include?('yardoc') || types.include?('yard')
      generate_yri = types.include? 'yri'

      specs.each do |spec|
        gen_yard = generate_yard
        gen_yri = generate_yri
        gen_yri = false if gen_yard # never generate both, no need
        unless types.empty? # --no-document is not in effect
          # look at spec.metadata['yard.run'] for override
          run_yard = spec.metadata['yard.run']
          gen_yard = true if run_yard && run_yard != 'yri'
          gen_yri = true if run_yard == 'yri'
        end

        new(spec, gen_yard, gen_yri).generate
      end

      return unless generate_yard || generate_yri

      duration = (Time.now - start).to_i
      names = specs.map(&:name).join ', '

      say "Done installing documentation for #{names} after #{duration} seconds"
    end

    ##
    # Pre uninstalls hook that removes documentation
    #

    def self.removal_hook(uninstaller)
      new(uninstaller.spec).remove
    end

    ##
    # Loads the YARD generator

    def self.load_yard
      return if @yard_version

      require 'yard'

      @yard_version = Gem::Version.new ::YARD::VERSION
    end

    def initialize(spec, generate_yard = false, generate_yri = true)
      @doc_dir = spec.doc_dir
      @force = false
      @spec = spec

      @generate_yard = generate_yard
      @generate_yri = generate_yri

      @yard_dir = spec.doc_dir('yard')
      @yri_dir = spec.doc_dir('.yardoc')
    end

    def run_yardoc(*args)
      args << '--quiet' unless Gem.configuration.really_verbose
      args << '--backtrace' if Gem.configuration.backtrace
      unless File.file?(File.join(@spec.full_gem_path, '.yardopts'))
        args << @spec.require_paths
        unless @spec.extra_rdoc_files.empty?
          args << '-'
          args += @spec.extra_rdoc_files
        end
      end
      args = args.flatten.map(&:to_s)

      Dir.chdir(@spec.full_gem_path) do
        YARD::CLI::Yardoc.run(*args)
      end
    rescue Errno::EACCES => e
      dirname = File.dirname e.message.split("-")[1].strip
      raise Gem::FilePermissionError, dirname
    rescue => ex
      alert_error "While generating documentation for #{@spec.full_name}"
      ui.errs.puts "... MESSAGE:   #{ex}"
      ui.errs.puts "... YARDOC args: #{args.join(' ')}"
      ui.errs.puts "\t#{ex.backtrace.join("\n\t")}" if Gem.configuration.backtrace
      ui.errs.puts "(continuing with the rest of the installation)"
    end

    def install_yard
      FileUtils.rm_rf @yard_dir

      say "Installing YARD documentation for #{@spec.full_name}..."
      run_yardoc '--no-progress', '--db', @yri_dir, '-o', @yard_dir
    end

    def install_yri
      FileUtils.rm_rf @yri_dir

      say "Building YARD (yri) index for #{@spec.full_name}..."
      run_yardoc '--no-progress', '-c', '-n', '--db', @yri_dir
    end

    ##
    # Generates YARD and yri data

    def generate
      return if @spec.default_gem?
      return unless @generate_yri || @generate_yard

      setup

      install_yri if @generate_yri && (@force || !File.exist?(@yri_dir))

      install_yard if @generate_yard && (@force || !File.exist?(@yard_dir))
    end

    ##
    # Prepares the spec for documentation generation

    def setup
      self.class.load_yard

      if File.exist?(@doc_dir)
        raise Gem::FilePermissionError, @doc_dir unless File.writable?(@doc_dir)
      else
        FileUtils.mkdir_p @doc_dir
      end
    end

    def uninstall_yard
      if File.exist?(@yard_dir)
        raise Gem::FilePermissionError, @yard_dir unless File.writable?(@yard_dir)
        FileUtils.rm_rf @yard_dir
      end
    end

    def uninstall_yri
      if File.exist?(@yri_dir)
        raise Gem::FilePermissionError, @yri_dir unless File.writable?(@yri_dir)
        FileUtils.rm_rf @yri_dir
      end
    end

    ##
    # Removes YARD and yri data

    def remove
      uninstall_yri
      uninstall_yard
    end
  end
end

Gem.done_installing(&YARD::RubygemsHook.method(:generation_hook))
Gem.pre_uninstall(&YARD::RubygemsHook.method(:removal_hook))

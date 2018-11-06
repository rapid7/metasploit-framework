# frozen_string_literal: true
module YARD
  module CLI
    # A local documentation server
    # @since 0.6.0
    class Server < Command
      # @return [Hash] a list of options to pass to the doc server
      attr_accessor :options

      # @return [Hash] a list of options to pass to the web server
      attr_accessor :server_options

      # @return [Hash] a list of library names and yardoc files to serve
      attr_accessor :libraries

      # @return [YARD::Server::Adapter] the adapter to use for loading the web server
      attr_accessor :adapter

      # @return [Array<String>] a list of scripts to load
      # @since 0.6.2
      attr_accessor :scripts

      # @return [Array<String>] a list of template paths to register
      # @since 0.6.2
      attr_accessor :template_paths

      # Creates a new instance of the Server command line utility
      def initialize
        super
        self.scripts = []
        self.template_paths = []
        self.libraries = {}
        self.options = SymbolHash.new(false).update(
          :single_library => true,
          :caching => false
        )
        self.server_options = {:Port => 8808}
      end

      def description
        "Runs a local documentation server"
      end

      def run(*args)
        optparse(*args)

        select_adapter.setup
        load_scripts
        load_template_paths
        adapter.new(libraries, options, server_options).start
      end

      private

      def load_scripts
        scripts.each {|file| load_script(file) }
      end

      def load_template_paths
        return if YARD::Config.options[:safe_mode]
        Templates::Engine.template_paths |= template_paths
      end

      def select_adapter
        return adapter if adapter
        require 'rubygems'
        require 'rack'
        self.adapter = YARD::Server::RackAdapter
      rescue LoadError
        self.adapter = YARD::Server::WebrickAdapter
      end

      def add_libraries(args)
        (0...args.size).step(2) do |index|
          library = args[index]
          dir = args[index + 1]

          libver = nil
          if dir
            if File.exist?(dir)
              # Provided dir contains a .yardopts file
              libver = create_library_version_if_yardopts_exist(library, dir)
              libver ||= YARD::Server::LibraryVersion.new(library, nil, dir)
            end
          else
            # Check if this dir contains a .yardopts file
            pwd = Dir.pwd
            libver = create_library_version_if_yardopts_exist(library, pwd)

            # Check default location
            yfile = File.join(pwd, Registry::DEFAULT_YARDOC_FILE)
            libver ||= YARD::Server::LibraryVersion.new(library, nil, yfile)
          end

          # Register library
          if libver
            libver.yardoc_file = File.expand_path(libver.yardoc_file) if libver.yardoc_file
            libver.source_path = File.expand_path(libver.source_path) if libver.source_path
            libraries[library] ||= []
            libraries[library] |= [libver]
          else
            log.warn "Cannot find yardoc db for #{library}: #{dir.inspect}"
          end
        end
      end

      # @param [String] library The library name.
      # @param [String, nil] dir The argument provided on the CLI after the
      #   library name. Is supposed to point to either a project directory
      #   with a Yard options file, or a yardoc db.
      # @return [LibraryVersion, nil]
      def create_library_version_if_yardopts_exist(library, dir)
        if dir
          options_file = File.join(dir, Yardoc::DEFAULT_YARDOPTS_FILE)
          if File.exist?(options_file)
            # Found yardopts, extract db path
            yfile = extract_db_from_options_file(options_file)
            db = File.expand_path(yfile, dir)

            # Create libver
            libver = YARD::Server::LibraryVersion.new(library, nil, db)
            libver.source_path = dir
            libver
          end
        end
      end

      def add_gems
        require 'rubygems'
        YARD::GemIndex.each do |spec|
          libraries[spec.name] ||= []
          libraries[spec.name] |= [YARD::Server::LibraryVersion.new(spec.name, spec.version.to_s, nil, :gem)]
        end
      end

      def add_gems_from_gemfile(gemfile = nil)
        require 'bundler'
        gemfile ||= "Gemfile"
        if File.exist?("#{gemfile}.lock")
          Bundler::LockfileParser.new(File.read("#{gemfile}.lock")).specs.each do |spec|
            libraries[spec.name] ||= []
            libraries[spec.name] |= [YARD::Server::LibraryVersion.new(spec.name, spec.version.to_s, nil, :gem)]
          end
        else
          log.warn "Cannot find #{gemfile}.lock, ignoring --gemfile option"
        end
      rescue LoadError
        log.error "Bundler not available, ignoring --gemfile option"
      end

      def optparse(*args)
        opts = OptionParser.new
        opts.banner = 'Usage: yard server [options] [[library yardoc_file] ...]'
        opts.separator ''
        opts.separator 'Example: yard server -m yard .yardoc ruby-core ../ruby/.yardoc'
        opts.separator 'The above example serves documentation for YARD and Ruby-core'
        opts.separator ''
        opts.separator 'If no library/yardoc_file is specified, the server uses'
        opts.separator 'the name of the current directory and `.yardoc` respectively'
        opts.separator ''
        opts.separator "General Options:"
        opts.on('-m', '--multi-library', 'Serves documentation for multiple libraries') do
          options[:single_library] = false
        end
        opts.on('-c', '--cache', 'Caches all documentation to document root (see --docroot)') do
          options[:caching] = true
        end
        opts.on('-r', '--reload', 'Reparses the library code on each request') do
          options[:incremental] = true
        end
        opts.on('-g', '--gems', 'Serves documentation for installed gems') do
          add_gems
        end
        opts.on('-G', '--gemfile [GEMFILE]', 'Serves documentation for gems from Gemfile') do |gemfile|
          add_gems_from_gemfile(gemfile)
        end
        opts.on('-t', '--template-path PATH',
                'The template path to look for templates in. (used with -t).') do |path|
          template_paths << path
        end
        opts.separator ''
        opts.separator "Web Server Options:"
        opts.on('-d', '--daemon', 'Daemonizes the server process') do
          server_options[:daemonize] = true
        end
        opts.on('-B HOST', '--bind', 'The host address to bind to') do |host|
          server_options[:Host] = host.to_s
        end
        opts.on('-p PORT', '--port', 'Serves documentation on PORT') do |port|
          server_options[:Port] = port.to_i
        end
        opts.on('--docroot DOCROOT', 'Uses DOCROOT as document root') do |docroot|
          server_options[:DocumentRoot] = File.expand_path(docroot)
        end
        opts.on('-a', '--adapter ADAPTER', 'Use the ADAPTER (full Ruby class) for web server') do |adapter|
          if adapter.casecmp('webrick') == 0
            self.adapter = YARD::Server::WebrickAdapter
          elsif adapter.casecmp('rack') == 0
            self.adapter = YARD::Server::RackAdapter
          else
            self.adapter = eval(adapter) # rubocop:disable Lint/Eval
          end
        end
        opts.on('-s', '--server TYPE', 'Use a specific server type eg. thin,mongrel,cgi (Rack specific)') do |type|
          server_options[:server] = type
        end
        opts.on('--fork', 'Use process forking when serving requests') do
          options[:use_fork] = true
        end
        common_options(opts)
        opts.on('-e', '--load FILE', 'A Ruby script to load before the source tree is parsed.') do |file|
          scripts << file
        end
        parse_options(opts, args)

        if args.empty? && libraries.empty?
          # No args - try to use current dir
          add_libraries([File.basename(Dir.pwd), nil])

          # Generate doc for first time
          # This is not necessary but makes for a better first-run experience
          libver = libraries.empty? ? nil : libraries.values.first.first
          generate_doc_for_first_time(libver) if libver && !libver.ready?
        else
          add_libraries(args)
          options[:single_library] = false if libraries.size > 1
        end
      end

      def generate_doc_for_first_time(libver)
        log.enter_level(Logger::INFO) do
          yardoc_file = libver.yardoc_file.sub(%r{^#{Regexp.quote Dir.pwd}[\\/]+}, '')
          log.info "No yardoc db found in #{yardoc_file}, parsing source before starting server..."
        end
        Dir.chdir(libver.source_path) do
          Yardoc.run('-n')
        end
      end

      def extract_db_from_options_file(options_file)
        args = File.read_binary(options_file).shell_split
        db = YARD::Registry.yardoc_file
        opts = OptionParser.new
        opts.on('-b', '--db FILE') {|file| db = file }

        begin
          opts.parse!(args)
        rescue OptionParser::ParseError
          args.shift if args.first && args.first[0, 1] != '-'
          retry
        end

        db
      end
    end
  end
end

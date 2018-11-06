# frozen_string_literal: true
require 'thread'

module YARD
  module Server
    module Commands
      class LibraryOptions < CLI::YardocOptions
        def adapter; @command.adapter end
        def library; @command.library end
        def single_library; @command.single_library end
        def serializer; @command.serializer end
        def serialize; false end

        attr_accessor :command
        attr_accessor :frames

        def each(&block)
          super(&block)
          yield(:adapter, adapter)
          yield(:library, library)
          yield(:single_library, single_library)
          yield(:serializer, serializer)
        end
      end

      # This is the base command for all commands that deal directly with libraries.
      # Some commands do not, but most (like {DisplayObjectCommand}) do. If your
      # command deals with libraries directly, subclass this class instead.
      # See {Base} for notes on how to subclass a command.
      #
      # @abstract
      class LibraryCommand < Base
        begin
          Process.fork { exit 0 }
          CAN_FORK = true
        rescue Exception # rubocop:disable Lint/RescueException
          CAN_FORK = false
        end

        # @return [LibraryVersion] the object containing library information
        attr_accessor :library

        # @return [LibraryOptions] default options for the library
        attr_accessor :options

        # @return [Serializers::Base] the serializer used to perform file linking
        attr_accessor :serializer

        # @return [Boolean] whether router should route for multiple libraries
        attr_accessor :single_library

        # @return [Boolean] whether to reparse data
        attr_accessor :incremental

        # @return [Boolean] whether or not this adapter calls +fork+ when serving
        #   library requests. Defaults to false.
        attr_accessor :use_fork

        # Needed to synchronize threads in {#setup_yardopts}
        # @private
        @@library_chdir_lock = Mutex.new

        def initialize(opts = {})
          super
          self.serializer = DocServerSerializer.new
        end

        def call(request)
          if can_fork?
            call_with_fork(request) { super }
          else
            begin
              save_default_template_info
              call_without_fork(request) { super }
            ensure
              restore_template_info
            end
          end
        end

        private

        def call_without_fork(request)
          self.request = request
          self.options = LibraryOptions.new
          options.reset_defaults
          options.command = self
          setup_library
          options.title = "Documentation for #{library.name} " +
                          (library.version ? '(' + library.version + ')' : '')
          yield
        rescue LibraryNotPreparedError
          not_prepared
        end

        def call_with_fork(request, &block)
          reader, writer = IO.pipe

          fork do
            log.debug "[pid=#{Process.pid}] fork serving: #{request.path}"
            reader.close
            writer.print(Marshal.dump(call_without_fork(request, &block)))
          end

          writer.close
          Marshal.load(reader.read)
        end

        def can_fork?
          CAN_FORK && use_fork
        end

        def save_default_template_info
          @old_template_paths = Templates::Engine.template_paths.dup
          @old_extra_includes = Templates::Template.extra_includes.dup
        end

        def restore_template_info
          Templates::Engine.template_paths = @old_template_paths
          Templates::Template.extra_includes = @old_extra_includes
        end

        def setup_library
          library.prepare! if request.xhr? && request.query['process']
          load_yardoc
          setup_yardopts
          true
        end

        def setup_yardopts
          @@library_chdir_lock.synchronize do
            Dir.chdir(library.source_path) do
              yardoc = CLI::Yardoc.new
              if incremental
                yardoc.run('-c', '-n', '--no-stats')
              else
                yardoc.parse_arguments
              end
              yardoc.send(:verify_markup_options)
              yardoc.options.delete(:serializer)
              yardoc.options.delete(:serialize)
              options.update(yardoc.options.to_hash)
            end
          end
        end

        def load_yardoc
          raise LibraryNotPreparedError unless library.ready?
          if Thread.current[:__yard_last_yardoc__] == library.yardoc_file
            log.debug "Reusing yardoc file: #{library.yardoc_file}"
            return
          end
          Registry.clear
          Templates::ErbCache.clear!
          Registry.load_yardoc(library.yardoc_file)
          Thread.current[:__yard_last_yardoc__] = library.yardoc_file
        end

        def not_prepared
          options.update(:template => :doc_server, :type => :processing)
          self.caching = false
          self.status = 202
          self.body = render
          self.headers = {'Content-Type' => 'text/html'}
          [status, headers, [body]]
        end

        # Hack to load a custom fulldoc template object that does
        # not do any rendering/generation. We need this to access the
        # generate_*_list methods.
        def fulldoc_template
          tplopts = [options.template, :fulldoc, options.format]
          tplclass = Templates::Engine.template(*tplopts)
          obj = Object.new.extend(tplclass)
          class << obj; define_method(:init) {} end
          obj.class = tplclass
          obj.send(:initialize, options)
          class << obj
            attr_reader :contents
            define_method(:asset) {|_, contents| @contents = contents }
          end
          obj
        end
      end
    end
  end
end

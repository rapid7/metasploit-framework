# frozen_string_literal: true
require 'ostruct'

module YARD
  module Templates
    # This module manages all creation, handling and rendering of {Template}
    # objects.
    #
    # * To create a template object at a path, use {template}.
    # * To render a template, call {render}.
    # * To register a template path in the lookup paths, call {register_template_path}.
    module Engine
      class << self
        # @return [Array<String>] the list of registered template paths
        attr_accessor :template_paths

        # Registers a new template path in {template_paths}
        #
        # @param [String] path a new template path
        # @return [void]
        def register_template_path(path)
          template_paths.push(path) unless template_paths.include?(path)
        end

        # Creates a template module representing the path. Searches on disk
        # for the first directory named +path+ (joined by '/') within the
        # template paths and builds a template module for. All other matching
        # directories in other template paths will be included in the
        # generated module as mixins (for overriding).
        #
        # @param [Array<String, Symbol>] path a list of path components
        # @raise [ArgumentError] if the path does not exist within one of the
        #   {template_paths} on disk.
        # @return [Template] the module representing the template
        def template(*path)
          from_template = nil
          from_template = path.shift if path.first.is_a?(Template)
          path = path.join('/')
          full_paths = find_template_paths(from_template, path)

          path = File.cleanpath(path).gsub('../', '')
          raise ArgumentError, "No such template for #{path}" if full_paths.empty?
          mod = template!(path, full_paths)

          mod
        end

        # Forces creation of a template at +path+ within a +full_path+.
        #
        # @param [String] path the path name of the template
        # @param [Array<String>] full_paths the full path on disk of the template
        # @return [Template] the template module representing the +path+
        def template!(path, full_paths = nil)
          full_paths ||= [path]
          full_paths = [full_paths] unless full_paths.is_a?(Array)
          name = template_module_name(full_paths.first)
          begin; return const_get(name); rescue NameError; nil end

          mod = const_set(name, Module.new)
          mod.send(:include, Template)
          mod.send(:initialize, path, full_paths)
          mod
        end

        # Renders a template on a {CodeObjects::Base code object} using
        # a set of default (overridable) options. Either the +:object+
        # or +:type+ keys must be provided.
        #
        # If a +:serializer+ key is provided and +:serialize+ is not set to
        # false, the rendered contents will be serialized through the {Serializers::Base}
        # object. See {with_serializer}.
        #
        # @example Renders an object with html formatting
        #   Engine.render(:format => :html, :object => obj)
        # @example Renders without an object
        #   Engine.render(:type => :fulldoc, :otheropts => somevalue)
        # @param [Hash] options the options hash
        # @option options [Symbol] :format (:text) the default format
        # @option options [Symbol] :type (nil) the :object's type.
        # @option options [Symbol] :template (:default) the default template
        # @return [String] the rendered template
        def render(options = {})
          options = set_default_options(options)
          mod = template(options.template, options.type, options.format)

          if options.serializer && options.serialize != false
            with_serializer(options.object, options.serializer) { mod.run(options) }
          else
            mod.run(options)
          end
        end

        # Passes a set of objects to the +:fulldoc+ template for full documentation generation.
        # This is called by {CLI::Yardoc} to most commonly perform HTML
        # documentation generation.
        #
        # @param [Array<CodeObjects::Base>] objects a list of {CodeObjects::Base}
        #   objects to pass to the template
        # @param [Hash] options (see {render})
        # @return [void]
        def generate(objects, options = {})
          options = set_default_options(options)
          options.objects = objects
          options.object = Registry.root
          template(options.template, :fulldoc, options.format).run(options)
        end

        # Serializes the results of a block with a +serializer+ object.
        #
        # @param [CodeObjects::Base] object the code object to serialize
        # @param [Serializers::Base] serializer the serializer object
        # @yield a block whose result will be serialize
        # @yieldreturn [String] the contents to serialize
        # @see Serializers::Base
        def with_serializer(object, serializer)
          output = nil
          filename = serializer.serialized_path(object)
          if serializer.respond_to?(:basepath)
            filename = File.join(serializer.basepath, filename)
          end
          log.capture("Generating #{filename}", nil) do
            serializer.before_serialize if serializer
            output = yield
            if serializer
              serializer.serialize(object, output)
              serializer.after_serialize(output)
            end
          end
          output
        end

        private

        # Sets default options on the options hash
        #
        # @param [Hash] options the options hash
        # @option options [Symbol] :format (:text) the default format
        # @option options [Symbol] :type (nil) the :object's type, if provided
        # @option options [Symbol] :template (:default) the default template
        # @return [void]
        def set_default_options(options = {})
          if options.is_a?(Hash)
            options = TemplateOptions.new.tap do |o|
              o.reset_defaults
              o.update(options)
            end
          end
          options.type ||= options.object.type if options.object
          options
        end

        # Searches through the registered {template_paths} and returns
        # all full directories that have the +path+ within them on disk.
        #
        # @param [Template] from_template if provided, allows a relative
        #   path to be specified from this template's full path.
        # @param [String] path the path component to search for in the
        #   {template_paths}
        # @return [Array<String>] a list of full paths that are existing
        #   candidates for a template module
        def find_template_paths(from_template, path)
          paths = template_paths.dup
          paths = from_template.full_paths + paths if from_template

          paths.inject([]) do |acc, tp|
            full_path = File.cleanpath(File.join(tp, path))
            acc.unshift(full_path) if File.directory?(full_path)
            acc
          end.uniq
        end

        # The name of the module that represents a +path+
        #
        # @param [String] path the path to generate a module name for
        # @return [String] the module name
        def template_module_name(path)
          'Template_' + path.to_s.gsub(/[^a-z0-9]/i, '_')
        end
      end

      self.template_paths = []
    end

    Engine.register_template_path(File.join(YARD::ROOT, '..', 'templates'))
  end
end

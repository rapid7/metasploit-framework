# frozen_string_literal: true
require 'ostruct'

module YARD
  module Templates
    # An Options class containing default options for base template rendering. For
    # options specific to generation of HTML output, see {CLI::YardocOptions}.
    #
    # @see CLI::YardocOptions
    class TemplateOptions < YARD::Options
      # @return [Symbol] the template output format
      default_attr :format, :text

      # @return [Symbol] the template name used to render output
      default_attr :template, :default

      # @return [Symbol] the markup format to use when parsing docstrings
      default_attr :markup, :rdoc # default is :rdoc but falls back on :none

      # @return [String] the default return type for a method with no return tags
      default_attr :default_return, "Object"

      # @return [Boolean] whether void methods should show "void" in their signature
      default_attr :hide_void_return, false

      # @return [Boolean] whether code blocks should be syntax highlighted
      default_attr :highlight, true

      # @return [Class] the markup provider class for the markup format
      attr_accessor :markup_provider

      # @return [OpenStruct] an open struct containing any global state across all
      #   generated objects in a template.
      default_attr :globals, lambda { OpenStruct.new }
      alias __globals globals

      # @return [CodeObjects::Base] the main object being generated in the template
      attr_accessor :object

      # @return [CodeObjects::Base] the owner of the generated object
      attr_accessor :owner

      # @return [Symbol] the template type used to generate output
      attr_accessor :type

      # @return [Boolean] whether serialization should be performed
      default_attr :serialize, true

      # @return [Serializers::Base] the serializer used to generate links and serialize
      #   output. Serialization output only occurs if {#serialize} is +true+.
      attr_accessor :serializer

      # @deprecated use {#highlight} instead.
      # @return [Boolean] whether highlighting should be ignored
      attr_reader :no_highlight
      undef no_highlight
      def no_highlight; !highlight end
      def no_highlight=(value) self.highlight = !value end

      # @return [String] the title of a given page
      attr_accessor :page_title

      # @return [Boolean] whether the page is the "index"
      attr_accessor :index

      # @example A list of mixin path names (including wildcards)
      #   opts.embed_mixins #=> ['ClassMethods', '*Helper', 'YARD::*']
      # @return [Array<String>] an array of module name wildcards to embed into
      #   class documentation as if their methods were defined directly in the class.
      #   Useful for modules like ClassMethods. If the name contains '::', the module
      #   is matched against the full mixin path, otherwise only the module name is used.
      default_attr :embed_mixins, lambda { [] }

      # @param [CodeObjects::Base] mixin accepts any code object, but returns
      #   nil unless the object is a module.
      # @return [Boolean] whether a mixin matches the embed_mixins list
      # @return [nil] if the mixin is not a module object
      def embed_mixins_match?(mixin)
        return true if mixin == object # the method is not inherited
        return nil unless mixin.is_a?(CodeObjects::ModuleObject)
        embed_mixins.any? do |embed_mixin|
          re = /\A#{Regexp.quote(embed_mixin).gsub('\*', '.*')}\Z/
          matchstr = embed_mixin.include?("::") ? mixin.path : mixin.name
          re.match(matchstr.to_s)
        end
      end

      # @return [Verifier] the verifier object
      attr_accessor :verifier
    end
  end
end

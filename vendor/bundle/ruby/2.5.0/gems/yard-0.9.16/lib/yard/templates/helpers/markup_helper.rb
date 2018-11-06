# frozen_string_literal: true
require 'rubygems'

module YARD
  module Templates::Helpers
    # Helper methods for loading and managing markup types.
    module MarkupHelper
      class << self
        # Clears the markup provider cache information. Mainly used for testing.
        # @return [void]
        def clear_markup_cache
          self.markup_cache = {}
        end

        # @return [Hash{Symbol=>{(:provider,:class)=>Object}}] the cached markup providers
        # @private
        # @since 0.6.4
        attr_accessor :markup_cache
      end

      MarkupHelper.clear_markup_cache

      # The default list of markup providers for each markup type
      MARKUP_PROVIDERS = {
        :markdown => [
          {:lib => :redcarpet, :const => 'RedcarpetCompat'},
          {:lib => :rdiscount, :const => 'RDiscount'},
          {:lib => :kramdown, :const => 'Kramdown::Document'},
          {:lib => :bluecloth, :const => 'BlueCloth'},
          {:lib => :maruku, :const => 'Maruku'},
          {:lib => :'rpeg-markdown', :const => 'PEGMarkdown'},
          {:lib => :rdoc, :const => 'YARD::Templates::Helpers::Markup::RDocMarkdown'}
        ],
        :textile => [
          {:lib => :redcloth, :const => 'RedCloth'}
        ],
        :textile_strict => [
          {:lib => :redcloth, :const => 'RedCloth'}
        ],
        :rdoc => [
          {:lib => nil, :const => 'YARD::Templates::Helpers::Markup::RDocMarkup'}
        ],
        :org => [
          {:lib => :'org-ruby', :const => 'Orgmode::Parser'}
        ],
        :asciidoc => [
          {:lib => :asciidoctor, :const => 'Asciidoctor'}
        ],
        :ruby => [],
        :text => [],
        :pre  => [],
        :html => [],
        :none => []
      }

      # Returns a list of extensions for various markup types. To register
      # extensions for a type, add them to the array of extensions for the
      # type.
      # @since 0.6.0
      MARKUP_EXTENSIONS = {
        :html => ['htm', 'html', 'shtml'],
        :text => ['txt'],
        :textile => ['textile', 'txtile'],
        :asciidoc => ['asciidoc', 'ad', 'adoc', 'asc'],
        :markdown => ['markdown', 'md', 'mdown', 'mkd'],
        :rdoc => ['rdoc'],
        :org => ['org'],
        :ruby => ['rb', 'ru']
      }

      # Contains the Regexp object that matches the shebang line of extra
      # files to detect the markup type.
      MARKUP_FILE_SHEBANG = /\A#!(\S+)\s*$/

      # Attempts to load the first valid markup provider in {MARKUP_PROVIDERS}.
      # If a provider is specified, immediately try to load it.
      #
      # On success this sets `@markup_provider` and `@markup_class` to
      # the provider name and library constant class/module respectively for
      # the loaded provider.
      #
      # On failure this method will inform the user that no provider could be
      # found and exit the program.
      #
      # @return [Boolean] whether the markup provider was successfully loaded.
      def load_markup_provider(type = options.markup)
        return true if MarkupHelper.markup_cache[type]
        MarkupHelper.markup_cache[type] ||= {}

        providers = MARKUP_PROVIDERS[type.to_sym]
        return true if providers && providers.empty?
        if providers && options.markup_provider
          providers = providers.select {|p| p[:lib] == options.markup_provider }
        end

        if providers.nil? || providers.empty?
          log.error "Invalid markup type '#{type}' or markup provider " \
                    "(#{options.markup_provider}) is not registered."
          return false
        end

        # Search for provider, return the library class name as const if found
        providers.each do |provider|
          begin require provider[:lib].to_s; rescue LoadError; next end if provider[:lib]
          begin klass = eval("::" + provider[:const]); rescue NameError; next end # rubocop:disable Lint/Eval
          MarkupHelper.markup_cache[type][:provider] = provider[:lib] # Cache the provider
          MarkupHelper.markup_cache[type][:class] = klass
          return true
        end

        # Show error message telling user to install first potential provider
        lib = providers.first[:lib] || type
        log.error "Missing '#{lib}' gem for #{type.to_s.capitalize} formatting. Install it with `gem install #{lib}`"
        false
      end

      # Checks for a shebang or looks at the file extension to determine
      # the markup type for the file contents. File extensions are registered
      # for a markup type in {MARKUP_EXTENSIONS}.
      #
      # A shebang should be on the first line of a file and be in the form:
      #
      #   #!markup_type
      #
      # Standard markup types are text, html, rdoc, markdown, textile
      #
      # @param [String] contents Unused. Was necessary prior to 0.7.0.
      #   Newer versions of YARD use {CodeObjects::ExtraFileObject#contents}
      # @return [Symbol] the markup type recognized for the file
      # @see MARKUP_EXTENSIONS
      # @since 0.6.0
      def markup_for_file(contents, filename)
        return $1.to_sym if contents && contents =~ MARKUP_FILE_SHEBANG # Shebang support

        ext = (File.extname(filename)[1..-1] || '').downcase
        MARKUP_EXTENSIONS.each do |type, exts|
          return type if exts.include?(ext)
        end
        options.markup
      end

      # Strips any shebang lines on the file contents that pertain to
      # markup or preprocessing data.
      #
      # @deprecated Use {CodeObjects::ExtraFileObject#contents} instead
      # @return [String] the file contents minus any preprocessing tags
      # @since 0.6.0
      def markup_file_contents(contents)
        contents =~ MARKUP_FILE_SHEBANG ? $' : contents
      end

      # Gets the markup provider class/module constant for a markup type
      # Call {#load_markup_provider} before using this method.
      #
      # @param [Symbol] type the markup type (:rdoc, :markdown, etc.)
      # @return [Class] the markup class
      def markup_class(type = options.markup)
        load_markup_provider(type)
        MarkupHelper.markup_cache[type][:class]
      end

      # Gets the markup provider name for a markup type
      # Call {#load_markup_provider} before using this method.
      #
      # @param [Symbol] type the markup type (:rdoc, :markdown, etc.)
      # @return [Symbol] the markup provider name (usually the gem name of the library)
      def markup_provider(type = options.markup)
        MarkupHelper.markup_cache[type][:provider]
      end
    end
  end
end

# frozen_string_literal: true
module YARD
  module Server
    # A module that is mixed into {Templates::Template} in order to customize
    # certain template methods.
    module DocServerHelper
      # Modifies {Templates::Helpers::HtmlHelper#url_for} to return a URL instead
      # of a disk location.
      # @param (see Templates::Helpers::HtmlHelper#url_for)
      # @return (see Templates::Helpers::HtmlHelper#url_for)
      def url_for(obj, anchor = nil, relative = false) # rubocop:disable Lint/UnusedMethodArgument
        return '' if obj.nil?
        return url_for_index if obj == '_index.html'
        return abs_url(base_path(router.static_prefix), obj) if String === obj
        url = super(obj, anchor, false)
        return unless url
        abs_url(base_path(router.docs_prefix), url)
      end

      # Modifies {Templates::Helpers::HtmlHelper#url_for_file} to return a URL instead
      # of a disk location.
      # @param (see Templates::Helpers::HtmlHelper#url_for_file)
      # @return (see Templates::Helpers::HtmlHelper#url_for_file)
      def url_for_file(filename, anchor = nil)
        if filename.is_a?(CodeObjects::ExtraFileObject)
          filename = filename.filename
        end
        fname = filename.sub(%r{^#{@library.source_path.to_s}/}, '')
        fname += "##{anchor}" if anchor && !anchor.empty?
        abs_url(base_path(router.docs_prefix), 'file', fname)
      end

      # Modifies {Templates::Helpers::HtmlHelper#url_for_list} to return a URL
      # based on the list prefix instead of a HTML filename.
      # @param (see Templates::Helpers::HtmlHelper#url_for_list)
      # @return (see Templates::Helpers::HtmlHelper#url_for_list)
      def url_for_list(type)
        abs_url(base_path(router.list_prefix), type.to_s)
      end

      # Returns the frames URL for the page
      # @return (see Templates::Helpers::HtmlHelper#url_for_frameset)
      def url_for_frameset
        options.file ? url_for_file(options.file) : url_for(object)
      end

      # Returns the main URL, first checking a readme and then linking to the index
      # @return (see Templates::Helpers::HtmlHelper#url_for_main)
      def url_for_main
        options.readme ? url_for_file(options.readme) : url_for_index
      end

      # Returns the URL for the alphabetic index page
      # @return (see Templates::Helpers::HtmlHelper#url_for_index)
      def url_for_index
        abs_url(base_path(router.docs_prefix), 'index')
      end

      # @param path_components [Array<String>] components of a URL
      # @return [String] the absolute path from any mounted base URI.
      def abs_url(*path_components)
        File.join(router.request.script_name, *path_components)
      end

      # @example The base path for a library 'foo'
      #   base_path('docs') # => 'docs/foo'
      # @param [String] path the path prefix for a base path URI
      # @return [String] the base URI for a library with an extra +path+ prefix
      def base_path(path)
        libname = router.request.version_supplied ? @library.to_s : @library.name
        path + (@single_library ? '' : "/#{libname}")
      end

      # @return [Router] convenience method for accessing the router
      def router; @adapter.router end

      # @return [String] a timestamp for a given file
      def mtime(file)
        file = YARD::Server::Commands::StaticFileHelpers.find_file(@adapter, file)
        file ? File.mtime(file).to_i : nil
      end

      # @return [String] a URL for a file with a timestamp
      def mtime_url(file)
        url = url_for(file)
        time = mtime(file)
        url + (time ? "?#{time}" : "")
      end
    end
  end
end

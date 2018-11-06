require 'redcarpet.so'
require 'redcarpet/compat'

module Redcarpet
  VERSION = '3.4.0'

  class Markdown
    attr_reader :renderer
  end

  module Render

    # XHTML Renderer
    class XHTML < HTML
      def initialize(extensions = {})
        super(extensions.merge(xhtml: true))
      end
    end

    # HTML + SmartyPants renderer
    class SmartyHTML < HTML
      include SmartyPants
    end

    # A renderer object you can use to deal with users' input. It
    # enables +escape_html+ and +safe_links_only+ by default.
    #
    # The +block_code+ callback is also overriden not to include
    # the lang's class as the user can basically specify anything
    # with the vanilla one.
    class Safe < HTML
      def initialize(extensions = {})
        super({
          escape_html: true,
          safe_links_only: true
        }.merge(extensions))
      end

      def block_code(code, lang)
        "<pre>" \
          "<code>#{html_escape(code)}</code>" \
        "</pre>"
      end

      private

      # TODO: This is far from ideal to have such method as we
      # are duplicating existing code from Houdini. This method
      # should be defined at the C level.
      def html_escape(string)
        string.gsub(/['&\"<>\/]/, {
          '&' => '&amp;',
          '<' => '&lt;',
          '>' => '&gt;',
          '"' => '&quot;',
          "'" => '&#x27;',
          "/" => '&#x2F;',
        })
      end
    end

    # SmartyPants Mixin module
    #
    # Implements SmartyPants.postprocess, which
    # performs smartypants replacements on the HTML file,
    # once it has been fully rendered.
    #
    # To add SmartyPants postprocessing to your custom
    # renderers, just mixin the module `include SmartyPants`
    #
    # You can also use this as a standalone SmartyPants
    # implementation.
    #
    # Example:
    #
    #   # Mixin
    #   class CoolRenderer < HTML
    #     include SmartyPants
    #     # more code here
    #   end
    #
    #   # Standalone
    #   Redcarpet::Render::SmartyPants.render("you're")
    #
    module SmartyPants
      extend self
      def self.render(text)
        postprocess text
      end
    end
  end
end

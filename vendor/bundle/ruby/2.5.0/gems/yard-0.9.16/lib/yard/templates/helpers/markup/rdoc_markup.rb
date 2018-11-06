# frozen_string_literal: true
require 'thread'

module YARD
  module Templates
    module Helpers
      module Markup
        begin require 'rdoc'; rescue LoadError; nil end
        begin
          require 'rdoc/markup'
          require 'rdoc/markup/to_html'
          class RDocMarkup; MARKUP = RDoc::Markup end
          class RDocMarkupToHtml < RDoc::Markup::ToHtml
            if defined?(RDoc::VERSION) && RDoc::VERSION >= '4.0.0' &&
               defined?(RDoc::Options)
              def initialize
                options = RDoc::Options.new
                options.pipe = true
                super(options)
              end
            end
          end
        rescue LoadError
          begin
            require 'rdoc/markup/simple_markup'
            require 'rdoc/markup/simple_markup/to_html'
            class RDocMarkup; MARKUP = SM::SimpleMarkup end
            class RDocMarkupToHtml < SM::ToHtml; end
          rescue LoadError
            raise NameError, "could not load RDocMarkup (rdoc is not installed)"
          end
        end

        class RDocMarkup
          attr_accessor :from_path

          @@formatter = nil
          @@markup = nil
          @@mutex = nil

          def initialize(text)
            @text = text

            @@formatter ||= RDocMarkupToHtml.new
            @@markup ||= MARKUP.new
            @@mutex ||= Mutex.new
          end

          def to_html
            html = nil
            @@mutex.synchronize do
              @@formatter.from_path = from_path
              html = @@markup.convert(@text, @@formatter)
            end
            html = fix_dash_dash(html)
            html = fix_typewriter(html)
            html
          end

          private

          # Fixes RDoc behaviour with ++ only supporting alphanumeric text.
          #
          # @todo Refactor into own SimpleMarkup subclass
          def fix_typewriter(text)
            code_tags = 0
            text.gsub(%r{<(/)?(pre|code|tt)|(\s|^|>)\+(?! )([^\n\+]{1,900})(?! )\+}) do |str|
              closed = $1
              tag = $2
              first_text = $3
              type_text = $4

              if tag
                code_tags += (closed ? -1 : 1)
                next str
              end
              next str unless code_tags == 0
              first_text + '<tt>' + type_text + '</tt>'
            end
          end

          # Don't allow -- to turn into &#8212; element. The chances of this being
          # some --option is far more likely than the typographical meaning.
          #
          # @todo Refactor into own SimpleMarkup subclass
          def fix_dash_dash(text)
            text.gsub(/&#8212;(?=\S)/, '--')
          end
        end

        class RDocMarkupToHtml
          attr_accessor :from_path

          # Disable auto-link of URLs
          def handle_special_HYPERLINK(special) # rubocop:disable Style/MethodName
            @hyperlink ? special.text : super
          end

          def accept_paragraph(*args)
            par = args.last
            text = par.respond_to?(:txt) ? par.txt : par.text
            @hyperlink = text =~ /\{(https?:|mailto:|link:|www\.)/ ? true : false
            super
          end
        end
      end
    end
  end
end

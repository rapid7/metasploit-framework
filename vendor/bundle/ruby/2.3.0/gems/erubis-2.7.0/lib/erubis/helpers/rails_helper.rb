###
### $Release: 2.7.0 $
### copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
###


require 'erubis'
require 'erubis/preprocessing'


module Erubis

  class Eruby
    include ErboutEnhancer      # will generate '_erbout = _buf = ""; '
  end

  class FastEruby
    include ErboutEnhancer      # will generate '_erbout = _buf = ""; '
  end

  module Helpers

    ##
    ## helper module for Ruby on Rails
    ##
    ## howto:
    ##
    ## 1. add the folliwng code in your 'config/environment.rb'
    ##
    ##      require 'erubis/helpers/rails_helper'
    ##      #Erubis::Helpers::RailsHelper.engine_class = Erubis::Eruby # or Erubis::FastEruby
    ##      #Erubis::Helpers::RailsHelper.init_properties = {}
    ##      #Erubis::Helpers::RailsHelper.show_src = false       # set true for debugging
    ##      #Erubis::Helpers::RailsHelper.preprocessing = true   # set true to enable preprocessing
    ##
    ## 2. restart web server.
    ##
    ## if Erubis::Helper::Rails.show_src is true, Erubis prints converted Ruby code
    ## into log file ('log/development.log' or so). if false, it doesn't.
    ## if nil, Erubis prints converted Ruby code if ENV['RAILS_ENV'] == 'development'.
    ##
    module RailsHelper

      #cattr_accessor :init_properties
      @@engine_class = ::Erubis::Eruby
      #@@engine_class = ::Erubis::FastEruby
      def self.engine_class
        @@engine_class
      end
      def self.engine_class=(klass)
        @@engine_class = klass
      end

      #cattr_accessor :init_properties
      @@init_properties = {}
      def self.init_properties
        @@init_properties
      end
      def self.init_properties=(hash)
        @@init_properties = hash
      end

      #cattr_accessor :show_src
      @@show_src = nil
      def self.show_src
        @@show_src
      end
      def self.show_src=(flag)
        @@show_src = flag
      end

      #cattr_accessor :preprocessing
      @@preprocessing = false
      def self.preprocessing
        @@preprocessing
      end
      def self.preprocessing=(flag)
        @@preprocessing = flag
      end


      ## define class for backward-compatibility
      class PreprocessingEruby < Erubis::PreprocessingEruby   # :nodoc:
      end


      module TemplateConverter
        ## covert eRuby string into ruby code
        def _convert_template(template)    # :nodoc:
          #src = ::Erubis::Eruby.new(template).src
          klass      = ::Erubis::Helpers::RailsHelper.engine_class
          properties = ::Erubis::Helpers::RailsHelper.init_properties
          show_src   = ::Erubis::Helpers::RailsHelper.show_src
          show_src = ENV['RAILS_ENV'] == 'development' if show_src.nil?
          ## preprocessing
          if ::Erubis::Helpers::RailsHelper.preprocessing
            preprocessor = _create_preprocessor(template)
            template = preprocessor.evaluate(_preprocessing_context_object())
            _logger_info "** Erubis: preprocessed==<<'END'\n#{template}END\n" if show_src
          end
          ## convert into ruby code
          src = klass.new(template, properties).src
          #src.insert(0, '_erbout = ')
          _logger_info "** Erubis: src==<<'END'\n#{src}END\n" if show_src
          return src
        end
        def _create_preprocessor(template)
          return PreprocessingEruby.new(template, :escape=>true)
        end
        def _preprocessing_context_object
          return self
        end
        def _logger_info(message)
          logger.info message
        end
      end

    end

  end

end


class ActionView::Base   # :nodoc:
  include ::Erubis::Helpers::RailsHelper::TemplateConverter
  include ::Erubis::PreprocessingHelper
  private
  # convert template into ruby code
  def convert_template_into_ruby_code(template)
    #ERB.new(template, nil, @@erb_trim_mode).src
    return _convert_template(template)
  end
end


require 'action_pack/version'

rails22 = false

if ActionPack::VERSION::MAJOR >= 2             ### Rails 2.X


  if ActionPack::VERSION::MINOR >=2            ### Rails 2.2, 2.3 or higher

    rails22 = true
    module ActionView
      module TemplateHandlers
        class ErubisHandler < TemplateHandler
          include Compilable
          include ::Erubis::Helpers::RailsHelper::TemplateConverter
          include ::Erubis::PreprocessingHelper
          def compile(template)
            #src = ::ERB.new("<% __in_erb_template=true %>#{template.source}", nil, erb_trim_mode, '@output_buffer').src
            return _convert_template("<% __in_erb_template=true %>#{template.source}")
          end
        end
      end
      handler_klass = TemplateHandlers::ErubisHandler
      Template.register_default_template_handler :erb, handler_klass
      Template.register_template_handler :rhtml, handler_klass
    end
    module Erubis::Helpers::RailsHelper::TemplateConverter
      def _logger_info(message)
        #logger.info message   # logger.info seems not available in Rails 2.2
        ActionController::Base.new.logger.info message
      end
    end

  elsif ActionPack::VERSION::MINOR >=1            ### Rails 2.1

    module ActionView
      module TemplateHandlers # :nodoc:
        class ErubisHandler < TemplateHandler
          include Compilable
          include Erubis::Helpers::RailsHelper::TemplateConverter
          include Erubis::PreprocessingHelper
          #
          def compile(template)
            return _convert_template(template.source)   # template.is_a?(ActionView::Template)
          end
          def logger  #:nodoc:
            return @view.controller.logger
          end
          def _preprocessing_context_object  #:nodoc:
            return @view.controller.instance_variable_get('@template')
          end
          #
          def cache_fragment(block, name = {}, options = nil) #:nodoc:
            @view.fragment_for(block, name, options) do
              #eval(ActionView::Base.erb_variable, block.binding)
              eval('_buf', block.binding)
            end
          end
        end
      end
      handler_klass = TemplateHandlers::ErubisHandler
      Template.register_default_template_handler :erb, handler_klass
      Template.register_template_handler :rhtml, handler_klass
    end

  elsif ActionPack::VERSION::TINY >= 2         ### Rails 2.0.X (X >= 2)

    module ActionView
      module TemplateHandlers # :nodoc:
        class ErubisHandler < TemplateHandler
          include Erubis::Helpers::RailsHelper::TemplateConverter
          include Erubis::PreprocessingHelper
          def compile(template)
            return _convert_template(template)     # template.is_a?(String)
          end
          def logger  #:nodoc:
            return @view.controller.logger
          end
          def _preprocessing_context_object  #:nodoc:
            return @view.controller.instance_variable_get('@template')
          end
        end
      end
      Base.class_eval do
        handler_klass = TemplateHandlers::ErubisHandler
        register_default_template_handler :erb, handler_klass
        register_template_handler :rhtml, handler_klass
      end
    end

  else                                         ### Rails 2.0.0 or 2.0.1

    class ActionView::Base   # :nodoc:
      private
      # Method to create the source code for a given template.
      def create_template_source(extension, template, render_symbol, locals)
        if template_requires_setup?(extension)
          body = case extension.to_sym
            when :rxml, :builder
              content_type_handler = (controller.respond_to?(:response) ? "controller.response" : "controller")
              "#{content_type_handler}.content_type ||= Mime::XML\n" +
              "xml = Builder::XmlMarkup.new(:indent => 2)\n" +
              template +
              "\nxml.target!\n"
            when :rjs
              "controller.response.content_type ||= Mime::JS\n" +
              "update_page do |page|\n#{template}\nend"
          end
        else
          #body = ERB.new(template, nil, @@erb_trim_mode).src
          body = convert_template_into_ruby_code(template)
        end
        #
        @@template_args[render_symbol] ||= {}
        locals_keys = @@template_args[render_symbol].keys | locals
        @@template_args[render_symbol] = locals_keys.inject({}) { |h, k| h[k] = true; h }
        #
        locals_code = ""
        locals_keys.each do |key|
          locals_code << "#{key} = local_assigns[:#{key}]\n"
        end
        #
        "def #{render_symbol}(local_assigns)\n#{locals_code}#{body}\nend"
      end
    end

  end #if


else                                           ###  Rails 1.X


  if ActionPack::VERSION::MINOR > 12           ###  Rails 1.2

    class ActionView::Base   # :nodoc:
      private
      # Create source code for given template
      def create_template_source(extension, template, render_symbol, locals)
        if template_requires_setup?(extension)
          body = case extension.to_sym
            when :rxml
              "controller.response.content_type ||= 'application/xml'\n" +
              "xml = Builder::XmlMarkup.new(:indent => 2)\n" +
              template
            when :rjs
              "controller.response.content_type ||= 'text/javascript'\n" +
              "update_page do |page|\n#{template}\nend"
          end
        else
          #body = ERB.new(template, nil, @@erb_trim_mode).src
          body = convert_template_into_ruby_code(template)
        end
        #
        @@template_args[render_symbol] ||= {}
        locals_keys = @@template_args[render_symbol].keys | locals
        @@template_args[render_symbol] = locals_keys.inject({}) { |h, k| h[k] = true; h }
        #
        locals_code = ""
        locals_keys.each do |key|
          locals_code << "#{key} = local_assigns[:#{key}]\n"
        end
        #
        "def #{render_symbol}(local_assigns)\n#{locals_code}#{body}\nend"
      end
    end

  else                                         ###  Rails 1.1

    class ActionView::Base   # :nodoc:
      private
      # Create source code for given template
      def create_template_source(extension, template, render_symbol, locals)
        if template_requires_setup?(extension)
          body = case extension.to_sym
            when :rxml
              "xml = Builder::XmlMarkup.new(:indent => 2)\n" +
              "@controller.headers['Content-Type'] ||= 'application/xml'\n" +
              template
            when :rjs
              "@controller.headers['Content-Type'] ||= 'text/javascript'\n" +
              "update_page do |page|\n#{template}\nend"
          end
        else
          #body = ERB.new(template, nil, @@erb_trim_mode).src
          body = convert_template_into_ruby_code(template)
        end
        #
        @@template_args[render_symbol] ||= {}
        locals_keys = @@template_args[render_symbol].keys | locals
        @@template_args[render_symbol] = locals_keys.inject({}) { |h, k| h[k] = true; h }
        #
        locals_code = ""
        locals_keys.each do |key|
          locals_code << "#{key} = local_assigns[:#{key}] if local_assigns.has_key?(:#{key})\n"
        end
        #
        "def #{render_symbol}(local_assigns)\n#{locals_code}#{body}\nend"
      end
    end

  end #if

  ## make h() method faster (only for Rails 1.X)
  module ERB::Util  # :nodoc:
    ESCAPE_TABLE = { '&'=>'&amp;', '<'=>'&lt;', '>'=>'&gt;', '"'=>'&quot;', "'"=>'&#039;', }
    def h(value)
      value.to_s.gsub(/[&<>"]/) {|s| ESCAPE_TABLE[s] }
    end
    module_function :h
  end

end   ###


## finish
ActionController::Base.new.logger.info "** Erubis #{::Erubis::VERSION}"
$stdout.puts "** Erubis #{::Erubis::VERSION}" if rails22

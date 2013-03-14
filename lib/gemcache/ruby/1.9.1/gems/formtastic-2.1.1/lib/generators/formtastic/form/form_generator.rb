# encoding: utf-8
module Formtastic
  # Generates a Formtastic form partial based on an existing model. It will not overwrite existing
  # files without confirmation.
  #
  # @example
  #   $ rails generate formtastic:form Post
  # @example Copy the partial code to the pasteboard rather than generating a partial
  #   $ rails generate formtastic:form Post --copy
  # @example Return HAML output instead of default template engine
  #   $ rails generate formtastic:form Post --haml
  # @example Generate a form for specific model attributes
  #   $ rails generate formtastic:form Post title:string body:text
  # @example Generate a form for a specific controller
  #   $ rails generate formtastic:form Post --controller admin/posts
  class FormGenerator < Rails::Generators::NamedBase
    desc "Generates a Formtastic form partial based on an existing model."

    argument :name, :type => :string, :required => true, :banner => 'MODEL_NAME'
    argument :attributes, :type => :array, :default => [], :banner => 'attribute attribute'

    source_root File.expand_path('../../../templates', __FILE__)

    class_option :template_engine

    class_option :copy, :type => :boolean, :default => false, :group => :formtastic,
    :desc => 'Copy the generated code the clipboard instead of generating a partial file."'

    class_option :controller, :type => :string, :default => false, :group => :formtastic,
    :desc => 'Generate for custom controller/view path - in case model and controller namespace is different, i.e. "admin/posts"'

    def create_or_show
      @attributes = reflected_attributes if @attributes.empty?

      engine = options[:template_engine]

      if options[:copy]
        template = File.read("#{self.class.source_root}/_form.html.#{engine}")
        erb = ERB.new(template, nil, '-')
        generated_code = erb.result(binding).strip rescue nil
        puts "The following code has been copied to the clipboard, just paste it in your views:" if save_to_clipboard(generated_code)
        puts generated_code || "Error: Nothing generated. Does the model exist?"
      else
        empty_directory "app/views/#{controller_path}"
        template "_form.html.#{engine}", "app/views/#{controller_path}/_form.html.#{engine}"
      end
    end

    protected

    def controller_path
      @controller_path ||= if options[:controller]
        options[:controller].underscore
      else
        name.underscore.pluralize
      end
    end

    def reflected_attributes
      columns = content_columns
      columns += association_columns
    end

    def model
      @model ||= name.camelize.constantize
    end

    # Collects content columns (non-relation columns) for the current class.
    # Skips Active Record Timestamps.
    def content_columns
      model.content_columns.select do |column|
        !Formtastic::Helpers::InputsHelper::SKIPPED_COLUMNS.include? column.name.to_sym
      end
    end

    # Collects association columns (relation columns) for the current class. Skips polymorphic
    # associations because we can't guess which class to use for an automatically generated input.
    def association_columns
      model.reflect_on_all_associations(:belongs_to).select do |association_reflection|
        association_reflection.options[:polymorphic] != true
      end
    end

    def save_to_clipboard(data)
      return unless data

      begin
        case RUBY_PLATFORM
        when /win32/
          require 'win32/clipboard'
          ::Win32::Clipboard.data = data
        when /darwin/ # mac
          `echo "#{data}" | pbcopy`
        else # linux/unix
          `echo "#{data}" | xsel --clipboard` || `echo "#{data}" | xclip`
        end
      rescue LoadError
          false
      else
          true
      end
    end

  end
end
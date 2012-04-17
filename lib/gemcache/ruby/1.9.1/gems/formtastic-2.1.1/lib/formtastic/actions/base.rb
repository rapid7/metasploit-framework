module Formtastic
  module Actions
    module Base
      include Formtastic::LocalizedString
      
      attr_accessor :builder, :template, :object, :object_name, :method, :options
  
      def initialize(builder, template, object, object_name, method, options)
        @builder = builder
        @template = template
        @object = object
        @object_name = object_name
        @method = method
        @options = options.dup
        
        check_supported_methods!
      end
      
      def to_html
        raise NotImplementedError
      end
      
      def wrapper(&block)
        template.content_tag(:li, 
          template.capture(&block), 
          wrapper_html_options
        )
      end
      
      def wrapper_html_options
        wrapper_html_options_from_options.merge(default_wrapper_html_options)
      end
      
      def wrapper_html_options_from_options
        options[:wrapper_html] || {}
      end
      
      def default_wrapper_html_options
        {
          :class => wrapper_class,
          :id => wrapper_id
        }
      end
      
      def wrapper_class
        (default_wrapper_classes << wrapper_classes_from_options).join(" ")
      end
      
      def default_wrapper_classes
        ["action", "#{options[:as]}_action"]
      end
      
      def wrapper_classes_from_options
        classes = wrapper_html_options_from_options[:class] || []
        classes = classes.split(" ") if classes.is_a? String
        classes
      end
      
      def wrapper_html_options_from_options
        options[:wrapper_html] || {}
      end
      
      def wrapper_id
        wrapper_id_from_options || default_wrapper_id
      end
      
      def wrapper_id_from_options
        wrapper_html_options_from_options[:id]
      end
      
      def default_wrapper_id
        "#{object_name}_#{method}_action"
      end
      
      def supported_methods
        raise NotImplementedError
      end
      
      def text
        text = options[:label]
        text = (localized_string(i18n_key, text, :action, :model => sanitized_object_name) ||
               Formtastic::I18n.t(i18n_key, :model => sanitized_object_name)) unless text.is_a?(::String)
        text
      end
      
      def button_html
        default_button_html.merge(button_html_from_options || {}).merge(extra_button_html_options)
      end
      
      def button_html_from_options
        options[:button_html]
      end
      
      def extra_button_html_options
        {}
      end
      
      def default_button_html
        { :accesskey => accesskey }
      end
      
      def accesskey
        # TODO could be cleaner and separated, remember that nil is an allowed value for all of these
        return options[:accesskey] if options.key?(:accesskey)
        return options[:button_html][:accesskey] if options.key?(:button_html) && options[:button_html].key?(:accesskey)
        # TODO might be different for cancel, etc?
        return builder.default_commit_button_accesskey
      end
      
      
      protected
      
      def check_supported_methods!
        raise Formtastic::UnsupportedMethodForAction unless supported_methods.include?(method)
      end
      
      def i18n_key
        return submit_i18n_key if method == :submit
        method
      end
      
      def submit_i18n_key
        if new_or_persisted_object?
          key = @object.persisted? ? :update : :create
        else
          key = :submit
        end
      end
      
      def new_or_persisted_object?
        object && (object.respond_to?(:persisted?) || object.respond_to?(:new_record?))
      end
      
      def sanitized_object_name
        if new_or_persisted_object?
          # Deal with some complications with ActiveRecord::Base.human_name and two name models (eg UserPost)
          # ActiveRecord::Base.human_name falls back to ActiveRecord::Base.name.humanize ("Userpost")
          # if there's no i18n, which is pretty crappy.  In this circumstance we want to detect this
          # fall back (human_name == name.humanize) and do our own thing name.underscore.humanize ("User Post")
          if object.class.model_name.respond_to?(:human)
            sanitized_object_name = object.class.model_name.human
          else
            object_human_name = @object.class.human_name                # default is UserPost => "Userpost", but i18n may do better ("User post")
            crappy_human_name = @object.class.name.humanize             # UserPost => "Userpost"
            decent_human_name = @object.class.name.underscore.humanize  # UserPost => "User post"
            sanitized_object_name = (object_human_name == crappy_human_name) ? decent_human_name : object_human_name
          end
        else
          sanitized_object_name = object_name.to_s.send(builder.label_str_method)
        end
        sanitized_object_name
      end
      
    end
  end
end
module Formtastic
  # Implementation for looking up localized values within Formtastic using I18n, if no 
  # explicit value (like the `:label` option) is set and I18n-lookups are enabled in the
  # configuration.
  #
  # You can subclass this to implement your own Localizer, and configure Formtastic to use this
  # localizer with:
  #
  #   Formtastic::FormBuilder.i18n_localizer
  #
  # Enabled/disable i18n lookups completely with:
  #
  #   Formtastic::FormBuilder.i18n_lookups_by_default = true/false
  #
  # Lookup priority:
  #
  #   'formtastic.%{type}.%{model}.%{action}.%{attribute}'
  #   'formtastic.%{type}.%{model}.%{attribute}'
  #   'formtastic.%{type}.%{attribute}'
  #
  # Example:
  #
  #   'formtastic.labels.post.edit.title'
  #   'formtastic.labels.post.title'
  #   'formtastic.labels.title'
  class Localizer
    class Cache
      def get(key)
        cache[key]
      end
    
      def has_key?(key)
        cache.has_key?(key)
      end
    
      def set(key, result)
        cache[key] = result
      end
    
      def cache
        @cache ||= {}
      end
    
      def clear!
        cache.clear
      end
    end
        
    attr_accessor :builder
    
    def self.cache
      @cache ||= Cache.new
    end
    
    def initialize(current_builder)
      self.builder = current_builder 
    end

    def localize(key, value, type, options = {}) #:nodoc:
      key = value if value.is_a?(::Symbol)
      
      if value.is_a?(::String)
        escape_html_entities(value)
      else
        use_i18n = value.nil? ? i18n_lookups_by_default : (value != false)
        use_cache = i18n_cache_lookups
        cache = self.class.cache
        
        if use_i18n
          model_name, nested_model_name  = normalize_model_name(builder.model_name.underscore)

          action_name = builder.template.params[:action].to_s rescue ''
          attribute_name = key.to_s
          
          # look in the cache first
          if use_cache
            cache_key = [::I18n.locale, action_name, model_name, nested_model_name, attribute_name, key, value, type, options]
            return cache.get(cache_key) if cache.has_key?(cache_key)
          end

          defaults = Formtastic::I18n::SCOPES.reject do |i18n_scope|
            nested_model_name.nil? && i18n_scope.match(/nested_model/)
          end.collect do |i18n_scope|
            i18n_path = i18n_scope.dup
            i18n_path.gsub!('%{action}', action_name)
            i18n_path.gsub!('%{model}', model_name)
            i18n_path.gsub!('%{nested_model}', nested_model_name) unless nested_model_name.nil?
            i18n_path.gsub!('%{attribute}', attribute_name)
            i18n_path.gsub!('..', '.')
            i18n_path.to_sym
          end
          defaults << ''

          defaults.uniq!

          default_key = defaults.shift
          i18n_value = Formtastic::I18n.t(default_key,
            options.merge(:default => defaults, :scope => type.to_s.pluralize.to_sym))
          i18n_value = i18n_value.is_a?(::String) ? i18n_value : nil
          if i18n_value.blank? && type == :label
            # This is effectively what Rails label helper does for i18n lookup
            options[:scope] = [:helpers, type]
            options[:default] = defaults
            i18n_value = ::I18n.t(default_key, options)
          end
          
          # save the result to the cache
          result = (i18n_value.is_a?(::String) && i18n_value.present?) ? escape_html_entities(i18n_value) : nil
          cache.set(cache_key, result) if use_cache
          result
        end
      end
    end

    protected

    def normalize_model_name(name)
      if !name =~ /\[/ && builder.respond_to?(:parent_builder) && builder.parent_builder.object_name
        # Rails 3.1 nested builder case
        [builder.parent_builder.object_name.to_s, name]
      elsif name =~ /(.+)\[(.+)\]/
        # Rails 3 (and 3.1?) nested builder case with :post rather than @post
        [$1, $2]
      elsif builder.respond_to?(:options) && builder.options.key?(:parent_builder)
        # Rails 3.0 nested builder work-around case, where :parent_builder is provided by f.semantic_form_for
        [builder.options[:parent_builder].object_name.to_s, name]
      else
        # Non-nested case
        [name]
      end
    end

    def escape_html_entities(string) #:nodoc:
      if (builder.escape_html_entities_in_hints_and_labels) ||
         (self.respond_to?(:escape_html_entities_in_hints_and_labels) && escape_html_entities_in_hints_and_labels)
        string = builder.template.escape_once(string) unless string.respond_to?(:html_safe?) && string.html_safe? == true # Accept html_safe flag as indicator to skip escaping
      end
      string
    end

    def i18n_lookups_by_default
      builder.i18n_lookups_by_default
    end
    
    def i18n_cache_lookups
      builder.i18n_cache_lookups
    end

  end
end

module Formtastic
  module Helpers
    # @private
    module FieldsetWrapper

      protected

      # Generates a fieldset and wraps the content in an ordered list. When working
      # with nested attributes, it allows %i as interpolation option in :name. So you can do:
      #
      #   f.inputs :name => 'Task #%i', :for => :tasks
      #
      # or the shorter equivalent:
      #
      #   f.inputs 'Task #%i', :for => :tasks
      #
      # And it will generate a fieldset for each task with legend 'Task #1', 'Task #2',
      # 'Task #3' and so on.
      #
      # Note: Special case for the inline inputs (non-block):
      #   f.inputs "My little legend", :title, :body, :author   # Explicit legend string => "My little legend"
      #   f.inputs :my_little_legend, :title, :body, :author    # Localized (118n) legend with I18n key => I18n.t(:my_little_legend, ...)
      #   f.inputs :title, :body, :author                       # First argument is a column => (no legend)
      def field_set_and_list_wrapping(*args, &block) #:nodoc:
        contents = args.last.is_a?(::Hash) ? '' : args.pop.flatten
        html_options = args.extract_options!

        if block_given?
          contents = if template.respond_to?(:is_haml?) && template.is_haml?
            template.capture_haml(&block)
          else
            template.capture(&block)
          end
        end

        # Ruby 1.9: String#to_s behavior changed, need to make an explicit join.
        contents = contents.join if contents.respond_to?(:join)

        legend = field_set_legend(html_options)
        fieldset = template.content_tag(:fieldset,
          Formtastic::Util.html_safe(legend) << template.content_tag(:ol, Formtastic::Util.html_safe(contents)),
          html_options.except(:builder, :parent, :name)
        )

        fieldset
      end

      def field_set_legend(html_options)
        legend  = (html_options[:name] || '').to_s
        legend %= parent_child_index(html_options[:parent]) if html_options[:parent]
        legend  = template.content_tag(:legend, template.content_tag(:span, Formtastic::Util.html_safe(legend))) unless legend.blank?
        legend
      end

      # Gets the nested_child_index value from the parent builder. It returns a hash with each
      # association that the parent builds.
      def parent_child_index(parent) #:nodoc:
        # Could be {"post[authors_attributes]"=>0} or { :authors => 0 }
        duck = parent[:builder].instance_variable_get('@nested_child_index')
        
        # Could be symbol for the association, or a model (or an array of either, I think? TODO)
        child = parent[:for]
        # Pull a sybol or model out of Array (TODO: check if there's an Array)
        child = child.first if child.respond_to?(:first)
        # If it's an object, get a symbol from the class name
        child = child.class.name.underscore.to_sym unless child.is_a?(Symbol)
        
        key = "#{parent[:builder].object_name}[#{child}_attributes]"

        # TODO: One of the tests produces a scenario where duck is "0" and the test looks for a "1" 
        # in the legend, so if we have a number, return it with a +1 until we can verify this scenario.
        return duck + 1 if duck.is_a?(Fixnum)
        
        # First try to extract key from duck Hash, then try child
        i = (duck[key] || duck[child]).to_i + 1
      end

    end
  end
end

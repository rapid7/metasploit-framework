module Formtastic
  module Inputs
    # Boolean inputs are used to render an input for a single checkbox, typically for attributes
    # with a simple yes/no or true/false value. Boolean inputs are used by default for boolean
    # database columns.
    #
    # @example Full form context and markup
    #   <%= semantic_form_for @post %>
    #     <%= f.inputs do %>
    #       <%= f.input :published, :as => :boolean %>
    #     <% end %>
    #   <% end %>
    #
    #   <form...>
    #     <fieldset>
    #       <ol>
    #         <li class="boolean" id="post_published_input">
    #           <input type="hidden" name="post[published]" id="post_published" value="0">
    #           <label for="post_published">
    #             <input type="checkbox" name="post[published]" id="post_published" value="1">
    #             Published?
    #           </label>
    #         </li>
    #       </ol>
    #     </fieldset>
    #   </form>
    #
    # @example Set the values for the checked and unchecked states
    #   <%= f.input :published, :checked_value => "yes", :unchecked_value => "no" %>
    #
    # @see Formtastic::Helpers::InputsHelper#input InputsHelper#input for full documentation of all possible options.
    class BooleanInput
      include Base

      def to_html
        input_wrapping do
          hidden_field_html <<
          label_with_nested_checkbox
        end
      end

      def hidden_field_html
        template.hidden_field_tag(input_html_options[:name], unchecked_value, :id => nil, :disabled => input_html_options[:disabled] )
      end

      def label_with_nested_checkbox
        builder.label(
          method,
          label_text_with_embedded_checkbox,
          label_html_options
        )
      end

      def label_html_options
        prev = super
        prev[:class] = prev[:class] - ['label']
        
        input_html_options.merge(
          prev.merge(
            :id   => nil,
            :name => nil,
            :for  => input_html_options[:id]
          )
        )
      end

      def label_text_with_embedded_checkbox
        check_box_html << "" << label_text
      end

      def check_box_html
        template.check_box_tag("#{object_name}[#{method}]", checked_value, checked?, input_html_options)
      end

      def unchecked_value
        options[:unchecked_value] || '0'
      end

      def checked_value
        options[:checked_value] || '1'
      end

      def responds_to_global_required?
        false
      end

      def input_html_options
        {:name => input_html_options_name}.merge(super)
      end
      
      def input_html_options_name
        if builder.options.key?(:index)
          "#{object_name}[#{builder.options[:index]}][#{method}]"
        else
          "#{object_name}[#{method}]"
        end
      end

      def checked?
        object && ActionView::Helpers::InstanceTag.check_box_checked?(object.send(method), checked_value)
      end

    end
  end
end

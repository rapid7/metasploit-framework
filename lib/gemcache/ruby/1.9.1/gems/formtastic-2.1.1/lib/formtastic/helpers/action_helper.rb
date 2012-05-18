# -*- coding: utf-8 -*-
module Formtastic
  module Helpers
    module ActionHelper
      
      # Renders an action for the form (such as a subit/reset button, or a cancel link).
      #
      # Each action is wrapped in an `<li class="action">` tag with other classes added based on the
      # type of action being rendered, and is intended to be rendered inside a {#buttons}
      # block which wraps the button in a `fieldset` and `ol`.
      #
      # The textual value of the label can be changed from the default through the `:label`
      # argument or through i18n.
      #
      # @example Basic usage
      #   # form
      #   <%= semantic_form_for @post do |f| %>
      #     ...
      #     <%= f.actions do %>
      #       <%= f.action :submit %>
      #       <%= f.action :reset %>
      #       <%= f.action :cancel %>
      #     <% end %>
      #   <% end %>
      #
      #   # output
      #   <form ...>
      #     ...
      #     <fieldset class="buttons">
      #       <ol>
      #         <li class="action input_action">
      #           <input name="commit" type="submit" value="Create Post">
      #         </li>
      #         <li class="action input_action">
      #           <input name="commit" type="reset" value="Reset Post">
      #         </li>
      #         <li class="action link_action">
      #           <a href="/posts">Cancel Post</a>
      #         </li>
      #       </ol>
      #     </fieldset>
      #   </form>
      #
      # @example Set the value through the `:label` option
      #   <%= f.action :submit, :label => "Go" %>
      #
      # @example Pass HTML attributes down to the tag inside the wrapper
      #   <%= f.action :submit, :button_html => { :class => 'pretty', :accesskey => 'g', :disable_with => "Wait..." } %>
      #
      # @example Pass HTML attributes down to the `<li>` wrapper
      #   <%= f.action :submit, :wrapper_html => { :class => 'special', :id => 'whatever' } %>
      #
      # @option *args :label [String, Symbol]
      #   Override the label text with a String or a symbold for an i18n translation key
      #
      # @option *args :button_html [Hash]
      #   Override or add to the HTML attributes to be passed down to the `<input>` tag
      #
      # @option *args :wrapper_html [Hash]
      #   Override or add to the HTML attributes to be passed down to the wrapping `<li>` tag
      #
      # @todo document i18n keys
      def action(method, options = {})
        options = options.dup # Allow options to be shared without being tainted by Formtastic
        options[:as] ||= default_action_type(method, options)

        klass = action_class(options[:as])

        klass.new(self, template, @object, @object_name, method, options).to_html
      end

      protected

      def default_action_type(method, options = {}) #:nodoc:
        case method
          when :submit then :input
          when :reset then :input
          when :cancel then :link
        end
      end

      def action_class(as)
        @input_classes_cache ||= {}
        @input_classes_cache[as] ||= begin
          begin
            begin
              custom_action_class_name(as).constantize
            rescue NameError
              standard_action_class_name(as).constantize
            end
          rescue NameError
            raise Formtastic::UnknownActionError
          end
        end
      end

      # :as => :button # => ButtonAction
      def custom_action_class_name(as)
        "#{as.to_s.camelize}Action"
      end

      # :as => :button # => Formtastic::Actions::ButtonAction
      def standard_action_class_name(as)
        "Formtastic::Actions::#{as.to_s.camelize}Action"
      end

    end
  end
end

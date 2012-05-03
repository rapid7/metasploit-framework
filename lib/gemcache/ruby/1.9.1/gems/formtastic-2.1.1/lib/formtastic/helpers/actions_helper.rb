module Formtastic
  module Helpers
    # ActionsHelper encapsulates the responsibilties of the {#actions} DSL for acting on 
    # (submitting, cancelling, resetting) forms.
    #
    # {#actions} is a block helper used to wrap the form's actions (buttons, links) in a 
    # `<fieldset>` and `<ol>`, with each item in the list containing the markup representing a 
    # single action.
    #
    #     <%= semantic_form_for @post do |f| %>
    #       ...
    #       <%= f.actions do %>
    #         <%= f.action :submit
    #         <%= f.action :cancel
    #       <% end %>
    #     <% end %>
    #
    # The HTML output will be something like:
    #
    #     <form class="formtastic" method="post" action="...">
    #       ...
    #       <fieldset class="actions">
    #         <ol>
    #           <li class="action input_action">
    #             <input type="submit" name="commit" value="Create Post">
    #           </li>
    #           <li class="action input_action">
    #             <a href="/posts">Cancel Post</a>
    #           </li>
    #         </ol>
    #       </fieldset>
    #     </form>
    #
    # It's important to note that the `semantic_form_for` and {#actions} blocks wrap the
    # standard Rails `form_for` helper and form builder, so you have full access to every standard
    # Rails form helper, with any HTML markup and ERB syntax, allowing you to "break free" from
    # Formtastic when it doesn't suit to create your own buttons, links and actions:
    #
    #     <%= semantic_form_for @post do |f| %>
    #       ...
    #       <%= f.actions do %>
    #         <li class="save">
    #           <%= f.submit "Save" %>
    #         <li>
    #         <li class="cancel-link">
    #           Or <%= link_to "Cancel", posts_url %>
    #         <li>
    #       <% end %>
    #     <% end %>
    #
    # There are many other syntax variations and arguments to customize your form. See the
    # full documentation of {#actions} and {#action} for details.
    module ActionsHelper

      include Formtastic::Helpers::FieldsetWrapper
      
      # Creates a fieldset and ol tag wrapping for use around a set of buttons. It can be
      # called either with a block (in which you can do the usual Rails form stuff, HTML, ERB, etc),
      # or with a list of named actions. These two examples are functionally equivalent:
      #
      #     # With a block:
      #     <% semantic_form_for @post do |f| %>
      #       ...
      #       <% f.actions do %>
      #         <%= f.action :submit %>
      #         <%= f.action :cancel %>
      #       <% end %>
      #     <% end %>
      #
      #     # With a list of fields:
      #     <% semantic_form_for @post do |f| %>
      #       <%= f.actions :submit, :cancel %>
      #     <% end %>
      #
      #     # Output:
      #     <form ...>
      #       <fieldset class="buttons">
      #         <ol>
      #           <li class="action input_action">
      #             <input type="submit" ...>
      #           </li>
      #           <li class="action link_action">
      #             <a href="...">...</a>
      #           </li>
      #         </ol>
      #       </fieldset>
      #     </form>
      #
      # All options except `:name` and `:title` are passed down to the fieldset as HTML
      # attributes (`id`, `class`, `style`...). If provided, the `:name` or `:title` option is
      # passed into a `<legend>` inside the `<fieldset>` to name the set of buttons.
      #
      # @example Quickly add button(s) to the form, accepting all default values, options and behaviors
      #     <% semantic_form_for @post do |f| %>
      #       ...
      #       <%= f.actions %>
      #     <% end %>
      #
      # @example Specify which named buttons you want, accepting all default values, options and behaviors
      #     <% semantic_form_for @post do |f| %>
      #       ...
      #       <%= f.actions :commit %>
      #     <% end %>
      #
      # @example Specify which named buttons you want, and name the fieldset
      #     <% semantic_form_for @post do |f| %>
      #       ...
      #       <%= f.actions :commit, :name => "Actions" %>
      #       or
      #       <%= f.actions :commit, :label => "Actions" %>
      #     <% end %>
      #
      # @example Get full control over the action options
      #     <% semantic_form_for @post do |f| %>
      #       ...
      #       <%= f.actions do %>
      #         <%= f.action :label => "Go", :button_html => { :class => "pretty" :disable_with => "Wait..." }, :wrapper_html => { ... }
      #       <% end %>
      #     <% end %>
      #
      # @example Make your own actions with standard Rails helpers or HTML
      #     <% semantic_form_for @post do |f| %>
      #       <%= f.actions do %>
      #         <li>
      #           ...
      #         </li>
      #       <% end %>
      #     <% end %>
      #
      # @example Add HTML attributes to the fieldset
      #     <% semantic_form_for @post do |f| %>
      #       ...
      #       <%= f.actions :commit, :style => "border:1px;" %>
      #       or
      #       <%= f.actions :style => "border:1px;" do %>
      #         ...
      #       <% end %>
      #     <% end %>
      #
      # @option *args :label [String, Symbol]
      #   Optionally specify text for the legend of the fieldset
      #
      # @option *args :name [String, Symbol]
      #   Optionally specify text for the legend of the fieldset (alias for `:label`)
      #
      # @todo document i18n keys
      def actions(*args, &block)
        html_options = args.extract_options!
        html_options[:class] ||= "actions"

        if block_given?
          field_set_and_list_wrapping(html_options, &block)
        else
          args = default_actions if args.empty?
          contents = args.map { |action_name| action(action_name) }
          field_set_and_list_wrapping(html_options, contents)
        end
      end

      protected
      
      def default_actions
        [:submit]
      end

    end
  end
end
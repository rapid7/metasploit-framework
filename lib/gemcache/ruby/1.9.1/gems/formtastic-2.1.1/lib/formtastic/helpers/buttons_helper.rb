module Formtastic
  module Helpers

    # ButtonsHelper encapsulates the responsibilties of the {#buttons} and {#commit_button} helpers
    # for submitting forms.
    #
    # {#buttons} is used to wrap the form's button(s) and actions in a `<fieldset>` and `<ol>`,
    # with each item in the list containing the markup representing a single button.
    #
    # {#buttons} is usually called with a block containing a single {#commit_button} call:
    #
    #     <%= semantic_form_for @post do |f| %>
    #       ...
    #       <%= f.buttons do %>
    #         <%= f.commit_button
    #       <% end %>
    #     <% end %>
    #
    # The HTML output will be something like:
    #
    #     <form class="formtastic" method="post" action="...">
    #       ...
    #       <fieldset class="buttons">
    #         <ol>
    #           <li class="commit button">
    #             <input type="submit" name="commit" value="Create Post" class="create">
    #           </li>
    #         </ol>
    #       </fieldset>
    #     </form>
    #
    # While this may seem slightly over-engineered, it is consistent with the way form inputs are
    # handled, and makes room for other types of buttons and actions in future versions (such as
    # cancel buttons or links, reset buttons and even alternate actions like 'save and continue
    # editing').
    #
    # It's important to note that the `semantic_form_for` and {#buttons} blocks wrap the
    # standard Rails `form_for` helper and form builder, so you have full access to every standard
    # Rails form helper, with any HTML markup and ERB syntax, allowing you to "break free" from
    # Formtastic when it doesn't suit to create your own buttons, links and actions:
    #
    #     <%= semantic_form_for @post do |f| %>
    #       ...
    #       <%= f.buttons do %>
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
    # full documentation of {#buttons} and {#commit_button} for details.
    #
    # @deprecated ButtonsHelper will be removed after 2.1
    module ButtonsHelper
      include Formtastic::Helpers::FieldsetWrapper
      include Formtastic::LocalizedString

      # Creates a fieldset and ol tag wrapping for use around a set of buttons. It can be
      # called either with a block (in which you can do the usual Rails form stuff, HTML, ERB, etc),
      # or with a list of named buttons. These two examples are functionally equivalent:
      #
      #     # With a block:
      #     <% semantic_form_for @post do |f| %>
      #       ...
      #       <% f.buttons do %>
      #         <%= f.commit_button %>
      #       <% end %>
      #     <% end %>
      #
      #     # With a list of fields:
      #     <% semantic_form_for @post do |f| %>
      #       <%= f.buttons :commit %>
      #     <% end %>
      #
      #     # Output:
      #     <form ...>
      #       <fieldset class="buttons">
      #         <ol>
      #           <li class="commit button">
      #             <input type="submit" ...>
      #           </li>
      #         </ol>
      #       </fieldset>
      #     </form>
      #
      # Only one type of named button is supported at this time (:commit), and it's assumed to be
      # the default choice, so this is also functionally equivalent, but may change in the future:
      #
      #     # With no args:
      #     <% semantic_form_for @post do |f| %>
      #       ...
      #       <%= f.buttons %>
      #     <% end %>
      #
      # While this may seem slightly over-engineered, it is consistent with the way form inputs are
      # handled, and makes room for other types of buttons and actions in future versions (such as
      # cancel buttons or links, reset buttons and even alternate actions like 'save and continue
      # editing').
      #
      # All options except `:name` and `:title` are passed down to the fieldset as HTML
      # attributes (`id`, `class`, `style`...). If provided, the `:name` or `:title` option is
      # passed into a `<legend>` inside the `<fieldset>` to name the set of buttons.
      #
      # @example Quickly add button(s) to the form, accepting all default values, options and behaviors
      #     <% semantic_form_for @post do |f| %>
      #       ...
      #       <%= f.buttons %>
      #     <% end %>
      #
      # @example Specify which named buttons you want, accepting all default values, options and behaviors
      #     <% semantic_form_for @post do |f| %>
      #       ...
      #       <%= f.buttons :commit %>
      #     <% end %>
      #
      # @example Specify which named buttons you want, and name the fieldset
      #     <% semantic_form_for @post do |f| %>
      #       ...
      #       <%= f.buttons :commit, :name => "Actions" %>
      #       or
      #       <%= f.buttons :commit, :label => "Actions" %>
      #     <% end %>
      #
      # @example Get full control over the commit_button options
      #     <% semantic_form_for @post do |f| %>
      #       ...
      #       <%= f.buttons do %>
      #         <%= f.commit_button :label => "Go", :button_html => { :class => "pretty" :disable_with => "Wait..." }, :wrapper_html => { ... }
      #       <% end %>
      #     <% end %>
      #
      # @example Make your own custom buttons, links or actions with standard Rails helpers or HTML
      #     <% semantic_form_for @post do |f| %>
      #       ...
      #       <%= f.buttons do %>
      #         <li class="submit">
      #           <%= f.submit "Submit" %>
      #         </li>
      #         <li class="reset">
      #           <input type="reset" value="Reset">
      #         </li>
      #         <li class="cancel">
      #           <%= link_to "Cancel", posts_url %>
      #         </li>
      #       <% end %>
      #     <% end %>
      #
      # @example Add HTML attributes to the fieldset
      #     <% semantic_form_for @post do |f| %>
      #       ...
      #       <%= f.buttons :commit, :style => "border:1px;" %>
      #       or
      #       <%= f.buttons :style => "border:1px;" do %>
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
      # @deprecated f.buttons is deprecated in favor of f.actions and will be removed after 2.1
      def buttons(*args, &block)
        ::ActiveSupport::Deprecation.warn("f.buttons is deprecated in favour of f.actions and will be removed from Formtastic after 2.1. Please see ActionsHelper and InputAction or ButtonAction for more information")
        
        html_options = args.extract_options!
        html_options[:class] ||= "buttons"

        if block_given?
          field_set_and_list_wrapping(html_options, &block)
        else
          args = [:commit] if args.empty?
          contents = args.map { |button_name| send(:"#{button_name}_button") }
          field_set_and_list_wrapping(html_options, contents)
        end
      end

      # Creates a submit input tag with the value "Save [model name]" (for existing records) or
      # "Create [model name]" (for new records) by default. The output is an `<input>` tag with the
      # `type` of `submit` and a class of either `create` or `update` (if Formtastic can determin if)
      # the record is new or not) with `submit` as a fallback class. The submit button is wrapped in
      # an `<li>` tag with a class of `commit`, and is intended to be rendered inside a {#buttons}
      # block which wraps the button in a `fieldset` and `ol`.
      #
      # The textual value of the label can be changed from this default through the `:label`
      # argument or through i18n.
      #
      # You can pass HTML attributes down to the `<input>` tag with the `:button_html` option, and
      # pass HTML attributes to the wrapping `<li>` tag with the `:wrapper_html` option.
      #
      # @example Basic usage
      #   # form
      #   <%= semantic_form_for @post do |f| %>
      #     ...
      #     <%= f.buttons do %>
      #       <%= f.commit_button %>
      #     <% end %>
      #   <% end %>
      #
      #   # output
      #   <form ...>
      #     ...
      #     <fieldset class="buttons">
      #       <ol>
      #         <li class="commit button">
      #           <input name="commit" type="submit" value="Create Post" class="create">
      #         </li>
      #       </ol>
      #     </fieldset>
      #   </form>
      #
      # @example Set the value through the `:label` option
      #   <%= f.commit_button :label => "Go" %>
      #
      # @example Set the value through the optional first argument (like Rails' `f.submit`)
      #   <%= f.commit_button "Go" %>
      #
      # @example Pass HTML attributes down to the `<input>`
      #   <%= f.commit_button :button_html => { :class => 'pretty', :accesskey => 'g', :disable_with => "Wait..." } %>
      #   <%= f.commit_button :label => "Go", :button_html => { :class => 'pretty', :accesskey => 'g', :disable_with => "Wait..." } %>
      #   <%= f.commit_button "Go", :button_html => { :class => 'pretty', :accesskey => 'g', :disable_with => "Wait..." } %>
      #
      # @example Pass HTML attributes down to the `<li>` wrapper
      #   <%= f.commit_button :wrapper_html => { :class => 'special', :id => 'whatever' } %>
      #   <%= f.commit_button :label => "Go", :wrapper_html => { :class => 'special', :id => 'whatever' } %>
      #   <%= f.commit_button "Go", :wrapper_html => { :class => 'special', :id => 'whatever' } %>
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
      # @todo strange that `:accesskey` seems to be supported in the top level args as well as `:button_html`
      # @deprecated f.commit_button is deprecated in favor of f.actions and will be removed after 2.1
      def commit_button(*args)
        ::ActiveSupport::Deprecation.warn("f.commit_button is deprecated in favour of f.action(:submit) and will be removed from Formtastic after 2.1. Please see ActionsHelper and InputAction or ButtonAction for more information")
        
        options = args.extract_options!
        text = options.delete(:label) || args.shift

        text = (localized_string(commit_button_i18n_key, text, :action, :model => commit_button_object_name) ||
                Formtastic::I18n.t(commit_button_i18n_key, :model => commit_button_object_name)) unless text.is_a?(::String)

        button_html = options.delete(:button_html) || {}
        button_html[:id] ||= "#{@object_name}_submit"
        button_html.merge!(:class => [button_html[:class], commit_button_i18n_key].compact.join(' '))

        wrapper_html = options.delete(:wrapper_html) || {}
        wrapper_html[:class] = (commit_button_wrapper_html_class << wrapper_html[:class]).flatten.compact.join(' ')

        accesskey = (options.delete(:accesskey) || default_commit_button_accesskey) unless button_html.has_key?(:accesskey)
        button_html = button_html.merge(:accesskey => accesskey) if accesskey

        template.content_tag(:li, Formtastic::Util.html_safe(submit(text, button_html)), wrapper_html)
      end

      def commit_button_object_name
        if new_or_persisted_object?
          # Deal with some complications with ActiveRecord::Base.human_name and two name models (eg UserPost)
          # ActiveRecord::Base.human_name falls back to ActiveRecord::Base.name.humanize ("Userpost")
          # if there's no i18n, which is pretty crappy.  In this circumstance we want to detect this
          # fall back (human_name == name.humanize) and do our own thing name.underscore.humanize ("User Post")
          if @object.class.model_name.respond_to?(:human)
            object_name = @object.class.model_name.human
          else
            object_human_name = @object.class.human_name                # default is UserPost => "Userpost", but i18n may do better ("User post")
            crappy_human_name = @object.class.name.humanize             # UserPost => "Userpost"
            decent_human_name = @object.class.name.underscore.humanize  # UserPost => "User post"
            object_name = (object_human_name == crappy_human_name) ? decent_human_name : object_human_name
          end
        else
          object_name = @object_name.to_s.send(label_str_method)
        end

        object_name
      end

      def commit_button_i18n_key
        if new_or_persisted_object?
          key = @object.persisted? ? :update : :create
        else
          key = :submit
        end

        key
      end

      def commit_button_wrapper_html_class
        ['commit', 'button'] # TODO: Add class reflecting on form action.
      end

      def new_or_persisted_object?
        @object && (@object.respond_to?(:persisted?) || @object.respond_to?(:new_record?))
      end

    end
  end
end
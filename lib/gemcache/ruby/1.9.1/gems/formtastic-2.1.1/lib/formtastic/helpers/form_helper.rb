module Formtastic
  module Helpers

    # FormHelper provides a handful of wrappers around Rails' built-in form helpers methods to set
    # the `:builder` option to `Formtastic::FormBuilder` and apply some class names to the `<form>`
    # tag.
    #
    # The following methods are wrapped:
    #
    # * `semantic_form_for` to `form_for`
    # * `semantic_fields_for` to `fields_for`
    # * `semantic_remote_form_for` and `semantic_form_remote_for` to `remote_form_for`
    #
    # The following two examples are effectively equivalent:
    #
    #     <%= form_for(@post, :builder => Formtastic::FormBuilder, :class => 'formtastic post') do |f| %>
    #       #...
    #     <% end %>
    #
    #     <%= semantic_form_for(@post) do |f| %>
    #       #...
    #     <% end %>
    #
    # This simple wrapping means that all arguments, options and variations supported by Rails' own
    # helpers are also supported by Formtastic.
    #
    # Since `Formtastic::FormBuilder` subclasses Rails' own `FormBuilder`, you have access to all
    # of Rails' built-in form helper methods such as `text_field`, `check_box`, `radio_button`,
    # etc **in addition to** all of Formtastic's additional helpers like {InputsHelper#inputs inputs},
    # {InputsHelper#input input}, {ButtonsHelper#buttons buttons}, etc:
    #
    #     <%= semantic_form_for(@post) do |f| %>
    #
    #       <!-- Formtastic -->
    #       <%= f.input :title %>
    #
    #       <!-- Rails -->
    #       <li class='something-custom'>
    #         <%= f.label :title %>
    #         <%= f.text_field :title %>
    #         <p class='hints'>...</p>
    #       </li>
    #     <% end %>
    #
    # Formtastic is a superset of Rails' FormBuilder. It deliberately avoids overriding or modifying
    # the behavior of Rails' own form helpers so that you can use Formtastic helpers when suited,
    # and fall back to regular Rails helpers, ERB and HTML when needed. In other words, you're never
    # fully committed to The Formtastic Way.
    module FormHelper

      # Allows the `:builder` option on `form_for` etc to be changed to your own which subclasses
      # `Formtastic::FormBuilder`. Change this from `config/initializers/formtastic.rb`.
      @@builder = Formtastic::FormBuilder
      mattr_accessor :builder

      # Allows the default class we add to all `<form>` tags to be changed from `formtastic` to
      # `whatever`. Change this from `config/initializers/formtastic.rb`.
      @@default_form_class = 'formtastic'
      mattr_accessor :default_form_class

      # Wrapper around Rails' own `form_for` helper to set the `:builder` option to
      # `Formtastic::FormBuilder` and to set some class names on the `<form>` tag such as
      # `formtastic` and the downcased and underscored model name (eg `post`).
      #
      # See Rails' `form_for` for full documentation of all supported arguments and options.
      #
      # Since `Formtastic::FormBuilder` subclasses Rails' own FormBuilder, you have access to all
      # of Rails' built-in form helper methods such as `text_field`, `check_box`, `radio_button`,
      # etc **in addition to** all of Formtastic's additional helpers like {InputsHelper#inputs inputs},
      # {InputsHelper#input input}, {ButtonsHelper#buttons buttons}, etc.
      #
      # Most of the examples below have been adapted from the examples found in the Rails `form_for`
      # documentation.
      #
      # @see http://api.rubyonrails.org/classes/ActionView/Helpers/FormHelper.html Rails' FormHelper documentation (`form_for`, etc)
      # @see http://api.rubyonrails.org/classes/ActionView/Helpers/FormBuilder.html Rails' FormBuilder documentaion (`text_field`, etc)
      # @see FormHelper The overview of the FormBuilder module
      #
      # @example Resource-oriented form generation
      #   <%= semantic_form_for @user do |f| %>
      #     <%= f.input :name %>
      #     <%= f.input :email %>
      #     <%= f.input :password %>
      #   <% end %>
      #
      # @example Generic form generation
      #   <%= semantic_form_for :user do |f| %>
      #     <%= f.input :name %>
      #     <%= f.input :email %>
      #     <%= f.input :password %>
      #   <% end %>
      #
      # @example Resource-oriented with custom URL
      #   <%= semantic_form_for(@post, :url => super_post_path(@post)) do |f| %>
      #     ...
      #   <% end %>
      #
      # @example Resource-oriented with namespaced routes
      #   <%= semantic_form_for([:admin, @post]) do |f| %>
      #     ...
      #   <% end %>
      #
      # @example Resource-oriented with nested routes
      #   <%= semantic_form_for([@user, @post]) do |f| %>
      #     ...
      #   <% end %>
      #
      # @example Rename the resource
      #   <%= semantic_form_for(@post, :as => :article) do |f| %>
      #     ...
      #   <% end %>
      #
      # @example Remote forms (unobtrusive JavaScript)
      #   <%= semantic_form_for(@post, :remote => true) do |f| %>
      #     ...
      #   <% end %>
      #
      # @example Namespaced forms all multiple Formtastic forms to exist on the one page without DOM id clashes and invalid HTML documents.
      #   <%= semantic_form_for(@post, :namespace => 'first') do |f| %>
      #     ...
      #   <% end %>
      #
      # @example Accessing a mixture of Formtastic helpers and Rails FormBuilder helpers.
      #   <%= semantic_form_for(@post) do |f| %>
      #     <%= f.input :title %>
      #     <%= f.input :body %>
      #     <li class="something-custom">
      #       <label><%= f.check_box :published %></label>
      #     </li>
      #   <% end %>
      #
      # @param record_or_name_or_array
      #   Same behavior as Rails' `form_for`
      #
      # @option *args [Hash] :html
      #   Pass HTML attributes into the `<form>` tag. Same behavior as Rails' `form_for`, except we add in some of our own classes.
      #
      # @option *args [String, Hash] :url
      #   A hash of URL components just like you pass into `link_to` or `url_for`, or a named route (eg `posts_path`). Same behavior as Rails' `form_for`.
      #
      # @option *args [String] :namespace
      def semantic_form_for(record_or_name_or_array, *args, &proc)
        options = args.extract_options!
        options[:builder] ||= @@builder
        options[:html] ||= {}
        options[:html][:novalidate] = !@@builder.perform_browser_validations unless options[:html].key?(:novalidate)
        @@builder.custom_namespace = options.delete(:namespace).to_s

        singularizer = defined?(ActiveModel::Naming.singular) ? ActiveModel::Naming.method(:singular) : ActionController::RecordIdentifier.method(:singular_class_name)

        class_names = options[:html][:class] ? options[:html][:class].split(" ") : []
        class_names << @@default_form_class
        class_names << case record_or_name_or_array
          when String, Symbol then record_or_name_or_array.to_s                                  # :post => "post"
          when Array then options[:as] || singularizer.call(record_or_name_or_array.last.class)  # [@post, @comment] # => "comment"
          else options[:as] || singularizer.call(record_or_name_or_array.class)                  # @post => "post"
        end
        options[:html][:class] = class_names.join(" ")

        with_custom_field_error_proc do
          self.form_for(record_or_name_or_array, *(args << options), &proc)
        end
      end

      # Wrapper around Rails' own `fields_for` helper to set the `:builder` option to
      # `Formtastic::FormBuilder`.
      #
      # @see #semantic_form_for
      def semantic_fields_for(record_name, record_object = nil, options = {}, &block)
        options, record_object = record_object, nil if record_object.is_a?(Hash) && record_object.extractable_options?
        options[:builder] ||= @@builder
        @@builder.custom_namespace = options.delete(:namespace).to_s # TODO needed?

        with_custom_field_error_proc do
          self.fields_for(record_name, record_object, options, &block)
        end
      end

      protected

      # Override the default ActiveRecordHelper behaviour of wrapping the input.
      # This gets taken care of semantically by adding an error class to the LI tag
      # containing the input.
      # @private
      FIELD_ERROR_PROC = proc do |html_tag, instance_tag|
        html_tag
      end

      def with_custom_field_error_proc(&block)
        default_field_error_proc = ::ActionView::Base.field_error_proc
        ::ActionView::Base.field_error_proc = FIELD_ERROR_PROC
        yield
      ensure
        ::ActionView::Base.field_error_proc = default_field_error_proc
      end


    end
  end
end

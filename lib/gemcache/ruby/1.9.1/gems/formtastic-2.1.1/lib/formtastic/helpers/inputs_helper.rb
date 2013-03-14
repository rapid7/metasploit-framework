module Formtastic
  module Helpers

    # {#inputs} is used to wrap a series of form items in a `<fieldset>` and `<ol>`, with each item
    # in the list containing the markup representing a single {#input}.
    #
    # {#inputs} is usually called with a block containing a series of {#input} methods:
    #
    #     <%= semantic_form_for @post do |f| %>
    #       <%= f.inputs do %>
    #         <%= f.input :title %>
    #         <%= f.input :body %>
    #       <% end %>
    #     <% end %>
    #
    # The HTML output will be something like:
    #
    #     <form class="formtastic" method="post" action="...">
    #       <fieldset>
    #         <ol>
    #           <li class="string required" id="post_title_input">
    #             ...
    #           </li>
    #           <li class="text required" id="post_body_input">
    #             ...
    #           </li>
    #         </ol>
    #       </fieldset>
    #     </form>
    #
    # It's important to note that the `semantic_form_for` and {#inputs} blocks wrap the
    # standard Rails `form_for` helper and FormBuilder, so you have full access to every standard
    # Rails form helper, with any HTML markup and ERB syntax, allowing you to "break free" from
    # Formtastic when it doesn't suit:
    #
    #     <%= semantic_form_for @post do |f| %>
    #       <%= f.inputs do %>
    #         <%= f.input :title %>
    #         <li>
    #           <%= f.text_area :body %>
    #         <li>
    #       <% end %>
    #     <% end %>
    #
    # @see Formtastic::Helpers::InputHelper#input
    module InputsHelper
      include Formtastic::Helpers::FieldsetWrapper
      include Formtastic::LocalizedString

      # Which columns to skip when automatically rendering a form without any fields specified.
      SKIPPED_COLUMNS = [:created_at, :updated_at, :created_on, :updated_on, :lock_version, :version]


      # {#inputs} creates an input fieldset and ol tag wrapping for use around a set of inputs.  It can be
      # called either with a block (in which you can do the usual Rails form stuff, HTML, ERB, etc),
      # or with a list of fields (accepting all default arguments and options). These two examples
      # are functionally equivalent:
      #
      #     # With a block:
      #     <% semantic_form_for @post do |form| %>
      #       <% f.inputs do %>
      #         <%= f.input :title %>
      #         <%= f.input :body %>
      #       <% end %>
      #     <% end %>
      #
      #     # With a list of fields (short hand syntax):
      #     <% semantic_form_for @post do |form| %>
      #       <%= f.inputs :title, :body %>
      #     <% end %>
      #
      #     # Output:
      #     <form ...>
      #       <fieldset class="inputs">
      #         <ol>
      #           <li class="string">...</li>
      #           <li class="text">...</li>
      #         </ol>
      #       </fieldset>
      #     </form>
      #
      # **Quick Forms**
      #
      # Quick, scaffolding-style forms can be easily rendered for rapid early development if called
      # without a block or a field list. In the case an input is rendered for **most** columns in
      # the model's database table (like Rails' scaffolding) plus inputs for some model associations.
      #
      # In this case, all inputs are rendered with default options and arguments. You'll want more
      # control than this in a production application, but it's a great way to get started, then
      # come back later to customise the form with a field list or a block of inputs.  Example:
      #
      #     <% semantic_form_for @post do |form| %>
      #       <%= f.inputs %>
      #     <% end %>
      #
      # **Nested Attributes**
      #
      # One of the most complicated parts of Rails forms comes when nesting the inputs for
      # attrinbutes on associated models. Formtastic can take the pain away for many (but not all)
      # situations.
      #
      # Given the following models:
      #
      #     # Models
      #     class User < ActiveRecord::Base
      #       has_one :profile
      #       accepts_nested_attributes_for :profile
      #     end
      #     class Profile < ActiveRecord::Base
      #       belongs_to :user
      #     end
      #
      # Formtastic provides a helper called `semantic_fields_for`, which wraps around Rails' built-in
      # `fields_for` helper for backwards compatibility with previous versions of Formtastic, and for
      # a consistent method naming API. The following examples are functionally equivalent:
      #
      #     <% semantic_form_for @user do |form| %>
      #       <%= f.inputs :name, :email %>
      #
      #       <% f.semantic_fields_for :profile do |profile| %>
      #         <% profile.inputs do %>
      #           <%= profile.input :biography %>
      #           <%= profile.input :twitter_name %>
      #         <% end %>
      #       <% end %>
      #     <% end %>
      #
      #     <% semantic_form_for @user do |form| %>
      #       <%= f.inputs :name, :email %>
      #
      #       <% f.fields_for :profile do |profile| %>
      #         <% profile.inputs do %>
      #           <%= profile.input :biography %>
      #           <%= profile.input :twitter_name %>
      #         <% end %>
      #       <% end %>
      #     <% end %>
      #
      # {#inputs} also provides a DSL similar to `fields_for` / `semantic_fields_for` to reduce the 
      # lines of code a little:
      #
      #     <% semantic_form_for @user do |f| %>
      #       <%= f.inputs :name, :email %>
      #
      #       <% f.inputs :for => :profile do %>
      #         <%= profile.input :biography %>
      #         <%= profile.input :twitter_name %>
      #         <%= profile.input :shoe_size %>
      #       <% end %>
      #     <% end %>
      #
      # The `:for` option also works with short hand syntax:
      #
      #     <% semantic_form_for @post do |form| %>
      #       <%= f.inputs :name, :email %>
      #       <%= f.inputs :biography, :twitter_name, :shoe_size, :for => :profile %>
      #     <% end %>
      #
      # {#inputs} will always create a new `<fieldset>` wrapping, so only use it when it makes sense
      # in the document structure and semantics (using `semantic_fields_for` otherwise).
      #
      # All options except `:name`, `:title` and `:for` will be passed down to the fieldset as HTML
      # attributes (id, class, style, etc).
      #
      # When nesting `inputs()` inside another `inputs()` block, the nested content will 
      # automatically be wrapped in an `<li>` tag to preserve the HTML validity (a `<fieldset>`
      # cannot be a direct descendant of an `<ol>`.
      #
      #
      # @option *args :for [Symbol, ActiveModel, Array]
      #   The contents of this option is passed down to Rails' fields_for() helper, so it accepts the same values.
      #
      # @option *args :name [String]
      #   The optional name passed into the `<legend>` tag within the fieldset (alias of `:title`)
      #
      # @option *args :title [String]
      #   The optional name passed into the `<legend>` tag within the fieldset (alias of `:name`)
      #
      #
      # @example Quick form: Render a scaffold-like set of inputs for automatically guessed attributes and simple associations on the model, with all default arguments and options
      #   <% semantic_form_for @post do |form| %>
      #     <%= f.inputs %>
      #   <% end %>
      #
      # @example Short hand: Render inputs for a named set of attributes and simple associations on the model, with all default arguments and options
      #   <% semantic_form_for @post do |form| %>
      #     <%= f.inputs, :title, :body, :user, :categories %>
      #   <% end %>
      #
      # @example Block: Render inputs for attributes and simple associations with full control over arguments and options
      #   <% semantic_form_for @post do |form| %>
      #     <%= f.inputs do %>
      #       <%= f.input :title ... %>
      #       <%= f.input :body ... %>
      #       <%= f.input :user ... %>
      #       <%= f.input :categories ... %>
      #     <% end %>
      #   <% end %>
      #
      # @example Multiple blocks: Render inputs in multiple fieldsets
      #   <% semantic_form_for @post do |form| %>
      #     <%= f.inputs do %>
      #       <%= f.input :title ... %>
      #       <%= f.input :body ... %>
      #     <% end %>
      #     <%= f.inputs do %>
      #       <%= f.input :user ... %>
      #       <%= f.input :categories ... %>
      #     <% end %>
      #   <% end %>
      #
      # @example Provide text for the `<legend>` to name a fieldset (with a block)
      #   <% semantic_form_for @post do |form| %>
      #     <%= f.inputs :name => 'Write something:' do %>
      #       <%= f.input :title ... %>
      #       <%= f.input :body ... %>
      #     <% end %>
      #     <%= f.inputs do :name => 'Advanced options:' do %>
      #       <%= f.input :user ... %>
      #       <%= f.input :categories ... %>
      #     <% end %>
      #   <% end %>
      #
      # @example Provide text for the `<legend>` to name a fieldset (with short hand)
      #   <% semantic_form_for @post do |form| %>
      #     <%= f.inputs :title, :body, :name => 'Write something:'%>
      #     <%= f.inputs :user, :cateogies, :name => 'Advanced options:' %>
      #   <% end %>
      #
      # @example Inputs for nested attributes (don't forget `accepts_nested_attributes_for` in your model, see Rails' `fields_for` documentation)
      #   <% semantic_form_for @user do |form| %>
      #     <%= f.inputs do %>
      #       <%= f.input :name ... %>
      #       <%= f.input :email ... %>
      #     <% end %>
      #     <%= f.inputs :for => :profile do |profile| %>
      #       <%= profile.input :user ... %>
      #       <%= profile.input :categories ... %>
      #     <% end %>
      #   <% end %>
      #
      # @example Inputs for nested record (don't forget `accepts_nested_attributes_for` in your model, see Rails' `fields_for` documentation)
      #   <% semantic_form_for @user do |form| %>
      #     <%= f.inputs do %>
      #       <%= f.input :name ... %>
      #       <%= f.input :email ... %>
      #     <% end %>
      #     <%= f.inputs :for => @user.profile do |profile| %>
      #       <%= profile.input :user ... %>
      #       <%= profile.input :categories ... %>
      #     <% end %>
      #   <% end %>
      #
      # @example Inputs for nested record with a different name (don't forget `accepts_nested_attributes_for` in your model, see Rails' `fields_for` documentation)
      #   <% semantic_form_for @user do |form| %>
      #     <%= f.inputs do %>
      #       <%= f.input :name ... %>
      #       <%= f.input :email ... %>
      #     <% end %>
      #     <%= f.inputs :for => [:user_profile, @user.profile] do |profile| %>
      #       <%= profile.input :user ... %>
      #       <%= profile.input :categories ... %>
      #     <% end %>
      #   <% end %>
      #
      # @example Nesting {#inputs} blocks requires an extra `<li>` tag for valid markup
      #   <% semantic_form_for @user do |form| %>
      #     <%= f.inputs do %>
      #       <%= f.input :name ... %>
      #       <%= f.input :email ... %>
      #       <li>
      #         <%= f.inputs :for => [:user_profile, @user.profile] do |profile| %>
      #           <%= profile.input :user ... %>
      #           <%= profile.input :categories ... %>
      #         <% end %>
      #       </li>
      #     <% end %>
      #   <% end %>
      def inputs(*args, &block)
        wrap_it = @already_in_an_inputs_block ? true : false
        @already_in_an_inputs_block = true
        
        title = field_set_title_from_args(*args)
        html_options = args.extract_options!
        html_options[:class] ||= "inputs"
        html_options[:name] = title

        out = begin
          if html_options[:for] # Nested form
            inputs_for_nested_attributes(*(args << html_options), &block)
          elsif block_given?
            field_set_and_list_wrapping(*(args << html_options), &block)
          else
            legend = args.shift if args.first.is_a?(::String)
            args = default_columns_for_object if @object && args.empty?
            contents = fieldset_contents_from_column_list(args)
            args.unshift(legend) if legend.present?
            field_set_and_list_wrapping(*((args << html_options) << contents))
          end
        end
        
        out = template.content_tag(:li, out, :class => "input") if wrap_it
        @already_in_an_inputs_block = wrap_it
        out
      end

      protected
      
      def default_columns_for_object
        cols  = association_columns(:belongs_to)
        cols += content_columns
        cols -= SKIPPED_COLUMNS
        cols.compact
      end
      
      def fieldset_contents_from_column_list(columns)
        columns.collect do |method|
          if @object
            if @object.class.respond_to?(:reflect_on_association)
              if (@object.class.reflect_on_association(method.to_sym) && @object.class.reflect_on_association(method.to_sym).options[:polymorphic] == true)
                raise PolymorphicInputWithoutCollectionError.new("Please provide a collection for :#{method} input (you'll need to use block form syntax). Inputs for polymorphic associations can only be used when an explicit :collection is provided.")
              end
            elsif @object.class.respond_to?(:associations)
              if (@object.class.associations[method.to_sym] && @object.class.associations[method.to_sym].options[:polymorphic] == true)
                raise PolymorphicInputWithoutCollectionError.new("Please provide a collection for :#{method} input (you'll need to use block form syntax). Inputs for polymorphic associations can only be used when an explicit :collection is provided.")
              end            
            end            
          end
          input(method.to_sym)
        end
      end
      
      # Collects association columns (relation columns) for the current form object class. Skips
      # polymorphic associations because we can't guess which class to use for an automatically
      # generated input.
      def association_columns(*by_associations) #:nodoc:
        if @object.present? && @object.class.respond_to?(:reflections)
          @object.class.reflections.collect do |name, association_reflection|
            if by_associations.present?
              if by_associations.include?(association_reflection.macro) && association_reflection.options[:polymorphic] != true
                name 
              end
            else
              name
            end
          end.compact
        else
          []
        end
      end

      # Collects content columns (non-relation columns) for the current form object class.
      def content_columns #:nodoc:
        # TODO: NameError is raised by Inflector.constantize. Consider checking if it exists instead.
        begin klass = model_name.constantize; rescue NameError; return [] end
        return [] unless klass.respond_to?(:content_columns)
        klass.content_columns.collect { |c| c.name.to_sym }.compact
      end

      # Deals with :for option when it's supplied to inputs methods. Additional
      # options to be passed down to :for should be supplied using :for_options
      # key.
      #
      # It should raise an error if a block with arity zero is given.
      def inputs_for_nested_attributes(*args, &block) #:nodoc:
        options = args.extract_options!
        args << options.merge!(:parent => { :builder => self, :for => options[:for] })

        fields_for_block = if block_given?
          raise ArgumentError, 'You gave :for option with a block to inputs method, ' <<
                               'but the block does not accept any argument.' if block.arity <= 0
          lambda do |f|
            contents = f.inputs(*args) do
              if block.arity == 1  # for backwards compatibility with REE & Ruby 1.8.x
                block.call(f)
              else
                index = parent_child_index(options[:parent]) if options[:parent]
                block.call(f, index)
              end
            end
            template.concat(contents)
          end
        else
          lambda do |f|
            contents = f.inputs(*args)
            template.concat(contents)
          end
        end

        fields_for_args = [options.delete(:for), options.delete(:for_options) || {}].flatten(1)
        fields_for(*fields_for_args, &fields_for_block)
      end

      def field_set_title_from_args(*args) #:nodoc:
        options = args.extract_options!
        options[:name] ||= options.delete(:title)
        title = options[:name]

        if title.blank?
          valid_name_classes = [::String, ::Symbol]
          valid_name_classes.delete(::Symbol) if !block_given? && (args.first.is_a?(::Symbol) && content_columns.include?(args.first))
          title = args.shift if valid_name_classes.any? { |valid_name_class| args.first.is_a?(valid_name_class) }
        end
        title = localized_string(title, title, :title) if title.is_a?(::Symbol)
        title
      end

    end
  end
end

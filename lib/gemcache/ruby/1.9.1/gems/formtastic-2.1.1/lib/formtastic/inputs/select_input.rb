module Formtastic
  module Inputs
    # A select input is used to render a `<select>` tag with a series of options to choose from.
    # It works for both single selections (like a `belongs_to` relationship, or "yes/no" boolean),
    # as well as multiple selections (like a `has_and_belongs_to_many`/`has_many` relationship,
    # for assigning many genres to a song, for example).
    #
    # This is the default input choice when:
    #
    # * the database column type is an `:integer` and there is an association (`belongs_to`)
    # * the database column type is a `:string` and the `:collection` option is used
    # * there an object with an association, but no database column on the object (`has_many`, etc)
    # * there is no object and the `:collection` option is used
    #
    # The flexibility of the `:collection` option (see examples) makes the :select input viable as
    # an alternative for many other input types. For example, instead of...
    #
    # * a `:string` input (where you want to force the user to choose from a few specific strings rather than entering anything)
    # * a `:boolean` checkbox input (where the user could choose yes or no, rather than checking a box)
    # * a `:date`, `:time` or `:datetime` input (where the user could choose from pre-selected dates)
    # * a `:number` input (where the user could choose from a set of pre-defined numbers)
    # * a `:time_zone` input (where you want to provide your own set of choices instead of relying on Rails)
    # * a `:country` input (no need for a plugin really)
    #
    # Within the standard `<li>` wrapper, the output is a `<label>` tag followed by a `<select>`
    # tag containing `<option>` tags.
    #
    # For inputs that map to associations on the object model, Formtastic will automatically load
    # in a collection of objects on the association as options to choose from. This might be an
    # `Author.all` on a `Post` form with an input for a `belongs_to :user` association, or a
    # `Tag.all` for a `Post` form with an input for a `has_and_belongs_to_many :tags` association.
    # You can override or customise this collection and the `<option>` tags it will render through
    # the `:collection` option (see examples).
    #
    # The way on which Formtastic renders the `value` attribute and content of each `<option>` tag
    # is customisable through the `:member_label` and `:member_value` options. When not provided,
    # we fall back to a list of methods to try on each object such as `:to_label`, `:name` and
    # `:to_s`, which are defined in the configurations `collection_label_methods` and
    # `collection_value_methods` (see examples below).
    #
    # @example Basic `belongs_to` example with full form context
    #
    #     <%= semantic_form_for @post do |f| %>
    #       <%= f.inputs do %>
    #         <%= f.input :author, :as => :select %>
    #       <% end %>
    #     <% end %>
    #
    #     <form...>
    #       <fieldset>
    #         <ol>
    #           <li class='select'>
    #             <label for="post_author_id">Author</label>
    #             <select id="post_author_id" name="post[post_author_id]">
    #               <option value=""></option>
    #               <option value="1">Justin</option>
    #               <option value="3">Kate</option>
    #               <option value="2">Amelia</option>
    #             </select>
    #           </li>
    #         </ol>
    #       </fieldset>
    #     </form>
    #
    # @example Basic `has_many` or `has_and_belongs_to_many` example with full form context
    #
    #     <%= semantic_form_for @post do |f| %>
    #       <%= f.inputs do %>
    #         <%= f.input :tags, :as => :select %>
    #       <% end %>
    #     <% end %>
    #
    #     <form...>
    #       <fieldset>
    #         <ol>
    #           <li class='select'>
    #             <label for="post_tag_ids">Author</label>
    #             <select id="post_tag_ids" name="post[tag_ids]" multiple="true">
    #               <option value="1">Ruby</option>
    #               <option value="6">Rails</option>
    #               <option value="3">Forms</option>
    #               <option value="4">Awesome</option>
    #             </select>
    #           </li>
    #         </ol>
    #       </fieldset>
    #     </form>
    #
    # @example Override Formtastic's assumption on when you need a multi select
    #   <%= f.input :authors, :as => :select, :input_html => { :multiple => true } %>
    #   <%= f.input :authors, :as => :select, :input_html => { :multiple => false } %>
    #
    # @example The `:collection` option can be used to customize the choices
    #   <%= f.input :author, :as => :select, :collection => @authors %>
    #   <%= f.input :author, :as => :select, :collection => Author.all %>
    #   <%= f.input :author, :as => :select, :collection => Author.some_named_scope %>
    #   <%= f.input :author, :as => :select, :collection => [Author.find_by_login("justin"), Category.find_by_name("kate")] %>
    #   <%= f.input :author, :as => :select, :collection => ["Justin", "Kate"] %>
    #   <%= f.input :author, :as => :select, :collection => [["Justin", "justin"], ["Kate", "kate"]] %>
    #   <%= f.input :author, :as => :select, :collection => [["Justin", "1"], ["Kate", "3"]] %>
    #   <%= f.input :author, :as => :select, :collection => [["Justin", 1], ["Kate", 3]] %>
    #   <%= f.input :author, :as => :select, :collection => 1..5 %>
    #   <%= f.input :author, :as => :select, :collection => "<option>your own options HTML string</option>" %>
    #   <%= f.input :author, :as => :select, :collection => options_for_select(...) %>
    #   <%= f.input :author, :as => :select, :collection => options_from_collection_for_select(...) %>
    #   <%= f.input :author, :as => :select, :collection => grouped_options_for_select(...) %>
    #   <%= f.input :author, :as => :select, :collection => time_zone_options_for_select(...) %>
    #
    # @example The `:member_label` can be used to call a different method (or a Proc) on each object in the collection for rendering the label text (it'll try the methods like `to_s` in `collection_label_methods` config by default)
    #   <%= f.input :author, :as => :select, :member_label => :name %>
    #   <%= f.input :author, :as => :select, :member_label => :name_with_post_count %>
    #   <%= f.input :author, :as => :select, :member_label => Proc.new { |a| "#{c.name} (#{pluralize("post", a.posts.count)})" } %>
    #
    # @example The `:member_value` can be used to call a different method (or a Proc) on each object in the collection for rendering the value for each checkbox (it'll try the methods like `id` in `collection_value_methods` config by default)
    #   <%= f.input :author, :as => :select, :member_value => :login %>
    #   <%= f.input :author, :as => :select, :member_value => Proc.new { |c| c.full_name.downcase.underscore } %>
    #
    # @example Set HTML attributes on the `<select>` tag with `:input_html`
    #   <%= f.input :authors, :as => :select, :input_html => { :size => 20, :multiple => true, :class => "special" } %>
    #
    # @example Set HTML attributes on the `<li>` wrapper with `:wrapper_html`
    #   <%= f.input :authors, :as => :select, :wrapper_html => { :class => "special" } %>
    #
    # @example Exclude, include, or customize the blank option at the top of the select. Always shown, even if the field already has a value. Suitable for optional inputs.
    #   <%= f.input :author, :as => :select, :include_blank => false %>
    #   <%= f.input :author, :as => :select, :include_blank => true %>   =>   <option value=""></option>
    #   <%= f.input :author, :as => :select, :include_blank => "No author" %>
    #
    # @example Exclude, include, or customize the prompt at the top of the select. Only shown if the field does not have a value. Suitable for required inputs.
    #   <%= f.input :author, :as => :select, :prompt => false %>
    #   <%= f.input :author, :as => :select, :prompt => true %>   =>   <option value="">Please select</option>
    #   <%= f.input :author, :as => :select, :prompt => "Please select an author" %>
    #
    #
    # @example Group options an `<optgroup>` with the `:group_by` and `:group_label` options (`belongs_to` associations only)
    #   <%= f.input :author, :as => :select, :group_by => :continent %>
    #
    # @see Formtastic::Helpers::InputsHelper#input InputsHelper#input for full documentation of all possible options.
    # @see Formtastic::Inputs::CheckBoxesInput CheckBoxesInput as an alternative for `has_many` and `has_and_belongs_to_many` associations
    # @see Formtastic::Inputs::RadioInput RadioInput as an alternative for `belongs_to` associations
    #
    # @todo Do/can we support the per-item HTML options like RadioInput?
    class SelectInput
      include Base
      include Base::Collections
      include Base::GroupedCollections

      def to_html
        input_wrapping do
          hidden_input <<
          label_html <<
          (options[:group_by] ? grouped_select_html : select_html)
        end
      end

      def select_html
        builder.select(input_name, collection, input_options, input_html_options)
      end

      def grouped_select_html
        builder.grouped_collection_select(
          input_name,
          grouped_collection,
          group_association,
          group_label_method,
          value_method,
          label_method,
          input_options,
          input_html_options
        )
      end

      def include_blank
        options.key?(:include_blank) ? options[:include_blank] : (single? && builder.include_blank_for_select_by_default)
      end
      
      def hidden_input
        if multiple?
          template.hidden_field_tag(input_html_options_name_multiple, '', :id => nil)
        else
          "".html_safe
        end
      end

      def prompt?
        !!options[:prompt]
      end

      def label_html_options
        super.merge(:for => input_html_options[:id])
      end

      def input_options
        super.merge :include_blank => (include_blank unless prompt?)
      end

      def input_html_options
        extra_input_html_options.merge(super)
      end
      
      def extra_input_html_options
        {
          :multiple => multiple?,
          :name => multiple? ? input_html_options_name_multiple : input_html_options_name
        }
      end
      
      def input_html_options_name
        if builder.options.key?(:index)
          "#{object_name}[#{builder.options[:index]}][#{association_primary_key}]"
        else
          "#{object_name}[#{association_primary_key}]"
        end
      end

      def input_html_options_name_multiple
        input_html_options_name + "[]"
      end

      def multiple_by_association?
        reflection && [ :has_many, :has_and_belongs_to_many ].include?(reflection.macro)
      end

      def multiple_by_options?
        options[:multiple] || (options[:input_html] && options[:input_html][:multiple])
      end

      def multiple?
        multiple_by_options? || multiple_by_association?
      end

      def single?
        !multiple?
      end

    end
  end
end
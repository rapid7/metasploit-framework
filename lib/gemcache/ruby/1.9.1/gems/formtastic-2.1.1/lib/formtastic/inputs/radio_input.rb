module Formtastic
  module Inputs

    # A radio input is used to render a series of radio inputs. This is an alternative input choice
    # for `belongs_to` associations like a `Post` belonging to a `Section` or an `Author`, or any
    # case where the user needs to make a single selection from a pre-defined collectioon of choices.
    #
    # Within the standard `<li>` wrapper, the output is a `<fieldset>` with a `<legend>` to
    # represent the "label" for the input, and an `<ol>` containing `<li>`s for each choice in
    # the association. Each `<li>` choice has a `<label>` containing an `<input type="radio">` and
    # the label text to describe each choice.
    #
    # Radio inputs can be considered as an alternative where a (non-multi) select input is used,
    # especially in cases where there are only a few choices, however they are not used by default
    # for any type of association or model attribute. You can choose to use a radio input instead of
    # a select with `:as => :radio`.
    #
    # Like a select input, the flexibility of the `:collection` option (see examples) makes the
    # :radio input viable as an alternative for many other input types. For example, instead of...
    #
    # * a `:string` input (where you want to force the user to choose from a few specific strings rather than entering anything)
    # * a `:boolean` checkbox input (where the user could choose yes or no, rather than checking a box)
    # * a `:date`, `:time` or `:datetime` input (where the user could choose from a small set of pre-determined dates)
    # * a `:number` input (where the user could choose from a small set of pre-defined numbers)
    # * a `:time_zone` input (where you want to provide your own small set of choices instead of relying on Rails)
    # * a `:country` input (where you want to provide a small set of choices, no need for a plugin really)
    #
    # For radio inputs that map to associations on the object model, Formtastic will automatically
    # load in a collection of objects on the association as options to choose from. This might be an
    # `Author.all` on a `Post` form with an input for a `belongs_to :user` association, or a
    # `Section.all` for a `Post` form with an input for a `belongs_to :section` association.
    # You can override or customise this collection through the `:collection` option (see examples).
    #
    # The way on which Formtastic renders the `value` attribute and label for each choice is
    # customisable through the `:member_label` and `:member_value` options (see examples below).
    # When not provided, we fall back to a list of methods to try on each object such as
    # `:to_label`, `:name` and `:to_s`, which are defined in the configurations
    # `collection_label_methods` and `collection_value_methods`.
    #
    # @example Basic `belongs_to` example with full form context
    #
    #     <%= semantic_form_for @post do |f| %>
    #       <%= f.inputs do %>
    #         <%= f.input :author, :as => :radio %>
    #       <% end %>
    #     <% end %>
    #
    #     <form...>
    #       <fieldset>
    #         <ol>
    #           <li class='radio'>
    #             <fieldset>
    #               <legend class="label"><label>Categories</label></legend>
    #               <ol>
    #                 <li>
    #                   <label for="post_author_id_1">
    #                     <input type="radio" id="post_author_id_1" value="1"> Justin
    #                   </label>
    #                 </li>
    #                 <li>
    #                   <label for="post_author_id_3">
    #                     <input type="radio" id="post_author_id_3" value="3"> Kate
    #                   </label>
    #                 </li>
    #                 <li>
    #                   <label for="post_author_id_2">
    #                     <input type="radio" id="post_author_id_2" value="2"> Amelia
    #                   </label>
    #                 </li>
    #               </ol>
    #             </fieldset>
    #           </li>
    #         </ol>
    #       </fieldset>
    #     </form>
    #
    # @example The `:collection` option can be used to customize the choices
    #   <%= f.input :author, :as => :radio, :collection => @authors %>
    #   <%= f.input :author, :as => :radio, :collection => Author.all %>
    #   <%= f.input :author, :as => :radio, :collection => Author.some_named_scope %>
    #   <%= f.input :author, :as => :radio, :collection => [Author.find_by_login("justin"), Category.find_by_name("kate")] %>
    #   <%= f.input :author, :as => :radio, :collection => ["Justin", "Kate"] %>
    #   <%= f.input :author, :as => :radio, :collection => [["Justin", "justin"], ["Kate", "kate"]] %>
    #   <%= f.input :author, :as => :radio, :collection => [["Justin", "1"], ["Kate", "3"]] %>
    #   <%= f.input :author, :as => :radio, :collection => [["Justin", 1], ["Kate", 3]] %>
    #   <%= f.input :author, :as => :radio, :collection => 1..5 %>
    #
    # @example The `:member_label` can be used to call a different method (or a Proc) on each object in the collection for rendering the label text (it'll try the methods like `to_s` in `collection_label_methods` config by default)
    #   <%= f.input :author, :as => :radio, :member_label => :name %>
    #   <%= f.input :author, :as => :radio, :member_label => :name_with_post_count
    #   <%= f.input :author, :as => :radio, :member_label => Proc.new { |a| "#{c.name} (#{pluralize("post", a.posts.count)})" }
    #
    # @example `:member_label` can be used with a helper method (both examples have the same result)
    #   <%= f.input :author, :as => :radio, :member_label => method(:fancy_label)
    #   <%= f.input :author, :as => :radio, :member_label => Proc.new { |author| fancy_label(author) }
    #
    # @example The `:member_value` can be used to call a different method (or a Proc) on each object in the collection for rendering the value for each checkbox (it'll try the methods like `id` in `collection_value_methods` config by default)
    #   <%= f.input :author, :as => :radio, :member_value => :login %>
    #   <%= f.input :author, :as => :radio, :member_value => Proc.new { |c| c.full_name.downcase.underscore }
    #
    # @example `:member_value` can be used with a helper method (both examples have the same result)
    #   <%= f.input :author, :as => :radio, :member_value => method(:some_helper)
    #   <%= f.input :author, :as => :radio, :member_value => Proc.new { |author| some_helper(author) }
    #
    # @example Set HTML attributes on each `<input type="radio">` tag with `:input_html`
    #   <%= f.input :author, :as => :radio, :input_html => { :size => 20, :multiple => true, :class => "special" } %>
    #
    # @example Set HTML attributes on the `<li>` wrapper with `:wrapper_html`
    #   <%= f.input :author, :as => :radio, :wrapper_html => { :class => "special" } %>
    #
    # @example `:value_as_class` can be used to add a class to the `<li>` wrapped around each choice using the radio value for custom styling of each choice
    #   <%= f.input :author, :as => :radio, :value_as_class => true %>
    #
    # @example Set HTML options on a specific radio input option with a 3rd element in the array for a collection member
    #   <%= f.input :author, :as => :radio, :collection => [["Test", 'test'], ["Try", "try", {:disabled => true}]]
    #
    # @see Formtastic::Helpers::InputsHelper#input InputsHelper#input for full documentation of all possible options.
    # @see Formtastic::Inputs::RadioInput as an alternative for `belongs_to` associations
    #
    # @todo :disabled like CheckBoxes?
    class RadioInput
      include Base
      include Base::Collections
      include Base::Choices
      
      def to_html
        input_wrapping do
          choices_wrapping do
            legend_html <<
            choices_group_wrapping do
              collection.map { |choice| 
                choice_wrapping(choice_wrapping_html_options(choice)) do
                  choice_html(choice)
                end
              }.join("\n").html_safe
            end
          end
        end
      end

      def choice_html(choice)        
        template.content_tag(:label,
          builder.radio_button(input_name, choice_value(choice), input_html_options.merge(choice_html_options(choice)).merge(:required => false)) << 
          choice_label(choice),
          label_html_options.merge(:for => choice_input_dom_id(choice), :class => nil)
        )
      end
      
      # Override to remove the for attribute since this isn't associated with any element, as it's
      # nested inside the legend.
      def label_html_options
        super.merge(:for => nil)
      end

    end
  end
end

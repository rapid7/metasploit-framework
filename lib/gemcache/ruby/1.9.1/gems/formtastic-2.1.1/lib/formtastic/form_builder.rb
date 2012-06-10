module Formtastic
  class FormBuilder < ActionView::Helpers::FormBuilder

    def self.configure(name, value = nil)
      class_attribute(name)
      self.send(:"#{name}=", value)
    end

    configure :custom_namespace
    configure :default_text_field_size
    configure :default_text_area_height, 20
    configure :default_text_area_width
    configure :all_fields_required_by_default, true
    configure :include_blank_for_select_by_default, true
    configure :required_string, proc { Formtastic::Util.html_safe(%{<abbr title="#{Formtastic::I18n.t(:required)}">*</abbr>}) }
    configure :optional_string, ''
    configure :inline_errors, :sentence
    configure :label_str_method, :humanize
    configure :collection_label_methods, %w[to_label display_name full_name name title username login value to_s]
    configure :collection_value_methods, %w[id to_s]
    configure :custom_inline_order, {}
    configure :file_methods, [ :file?, :public_filename, :filename ]
    configure :file_metadata_suffixes, ['content_type', 'file_name', 'file_size']
    configure :priority_countries, ["Australia", "Canada", "United Kingdom", "United States"]
    configure :i18n_lookups_by_default, true
    configure :i18n_cache_lookups, true
    configure :i18n_localizer, Formtastic::Localizer
    configure :escape_html_entities_in_hints_and_labels, true
    configure :default_commit_button_accesskey
    configure :default_inline_error_class, 'inline-errors'
    configure :default_error_list_class, 'errors'
    configure :default_hint_class, 'inline-hints'
    configure :use_required_attribute, false
    configure :perform_browser_validations, false

    attr_reader :template

    attr_reader :auto_index

    include Formtastic::HtmlAttributes

    include Formtastic::Helpers::InputHelper
    include Formtastic::Helpers::InputsHelper
    include Formtastic::Helpers::ButtonsHelper
    include Formtastic::Helpers::ActionHelper
    include Formtastic::Helpers::ActionsHelper
    include Formtastic::Helpers::ErrorsHelper
    
    # This is a wrapper around Rails' `ActionView::Helpers::FormBuilder#fields_for`, originally 
    # provided to ensure that the `:builder` from `semantic_form_for` was passed down into
    # the nested `fields_for`. Rails 3 no longer requires us to do this, so this method is
    # provided purely for backwards compatibility and DSL consistency.
    #
    # When constructing a `fields_for` form fragment *outside* of `semantic_form_for`, please use
    # `Formtastic::Helpers::FormHelper#semantic_fields_for`.
    #
    # @see http://api.rubyonrails.org/classes/ActionView/Helpers/FormBuilder.html#method-i-fields_for ActionView::Helpers::FormBuilder#fields_for
    # @see http://api.rubyonrails.org/classes/ActionView/Helpers/FormHelper.html#method-i-fields_for ActionView::Helpers::FormHelper#fields_for
    # @see Formtastic::Helpers::FormHelper#semantic_fields_for
    #
    # @example
    #   <% semantic_form_for @post do |post| %>
    #     <% post.semantic_fields_for :author do |author| %>
    #       <% author.inputs :name %>
    #     <% end %>
    #   <% end %>
    #
    #   <form ...>
    #     <fieldset class="inputs">
    #       <ol>
    #         <li class="string"><input type='text' name='post[author][name]' id='post_author_name' /></li>
    #       </ol>
    #     </fieldset>
    #   </form>
    #
    # @todo is there a way to test the params structure of the Rails helper we wrap to ensure forward compatibility?
    def semantic_fields_for(record_or_name_or_array, *args, &block)
      # Add a :parent_builder to the args so that nested translations can be possible in Rails 3
      options = args.extract_options!
      options[:parent_builder] ||= self
      
      # Wrap the Rails helper
      fields_for(record_or_name_or_array, *(args << options), &block)
    end
    
  end

end


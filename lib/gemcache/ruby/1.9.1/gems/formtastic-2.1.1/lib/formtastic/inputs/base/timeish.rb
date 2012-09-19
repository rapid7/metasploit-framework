module Formtastic
  module Inputs
    module Base
      # Timeish inputs (`:date`, `:datetime`, `:time`) are similar to the Rails date and time 
      # helpers (`date_select`, `datetime_select`, `time_select`), rendering a series of `<select>`
      # tags for each fragment (year, month, day, hour, minute, seconds). The fragments are then 
      # re-combined to a date by ActiveRecord through multi-parameter assignment.
      #
      # The mark-up produced by Rails is simple but far from ideal, with no way to label the 
      # individual fragments for accessibility, no fieldset to group the related fields, and no
      # legend describing the group. Formtastic addresses this within the standard `<li>` wrapper 
      # with a `<fieldset>` with a `<legend>` as a label, followed by an ordered list (`<ol>`) of 
      # list items (`<li>`), one for each fragment (year, month, ...). Each `<li>` fragment contains
      # a `<label>` (eg "Year") for the fragment, and a `<select>` containing `<option>`s (eg a 
      # range of years).
      #
      # In the supplied formtastic.css file, the resulting mark-up is styled to appear a lot like a
      # standard Rails date time select by:
      #
      # * styling the legend to look like the other labels (to the left hand side of the selects)
      # * floating the `<li>` fragments against each other as a single line
      # * hiding the `<label>` of each fragment with `display:none`
      #
      # @example `:date` input with full form context and sample HTMl output
      #
      #   <%= semantic_form_for(@post) do |f| %>
      #     <%= f.inputs do %>
      #       ...
      #       <%= f.input :publish_at, :as => :date %>
      #     <% end %>
      #   <% end %>
      #
      #   <form...>
      #     <fieldset class="inputs">
      #       <ol>
      #         <li class="date">
      #           <fieldset class="fragments">
      #             <ol class="fragments-group">
      #               <li class="fragment">
      #                 <label for="post_publish_at_1i">Year</label>
      #                 <select id="post_publish_at_1i" name="post[publish_at_1i]">...</select>
      #               </li>
      #               <li class="fragment">
      #                 <label for="post_publish_at_2i">Month</label>
      #                 <select id="post_publish_at_2i" name="post[publish_at_2i]">...</select>
      #               </li>
      #               <li class="fragment">
      #                 <label for="post_publish_at_3i">Day</label>
      #                 <select id="post_publish_at_3i" name="post[publish_at_3i]">...</select>
      #               </li>
      #             </ol>
      #           </fieldset>
      #         </li>
      #       </ol>
      #     </fieldset>
      #   </form>
      #       
      #
      # @example `:time` input
      #   <%= f.input :publish_at, :as => :time %>
      #
      # @example `:datetime` input
      #   <%= f.input :publish_at, :as => :datetime %>
      #
      # @example Change the labels for each fragment
      #   <%= f.input :publish_at, :as => :date, :labels => { :year => "Y", :month => "M", :day => "D" }  %>
      #
      # @example Skip a fragment (defaults to 1, skips all following fragments)
      #   <%= f.input :publish_at, :as => :datetime, :discard_minute => true  %>
      #   <%= f.input :publish_at, :as => :datetime, :discard_hour => true  %>
      #   <%= f.input :publish_at, :as => :datetime, :discard_day => true  %>
      #   <%= f.input :publish_at, :as => :datetime, :discard_month => true  %>
      #   <%= f.input :publish_at, :as => :datetime, :discard_year => true  %>
      #
      # @example Change the order
      #   <%= f.input :publish_at, :as => :date, :order => [:month, :day, :year]  %>
      #
      # @example Include seconds with times (excluded by default)
      #   <%= f.input :publish_at, :as => :time, :include_seconds => true %>
      #
      # @example Specify if there should be a blank option at the start of each select or not. Note that, unlike select inputs, :include_blank does not accept a string value.
      #   <%= f.input :publish_at, :as => :time, :include_blank => true %>
      #   <%= f.input :publish_at, :as => :time, :include_blank => false %>
      #
      # @todo Document i18n
      # @todo Check what other Rails options are supported (`start_year`, `end_year`, `use_month_numbers`, `use_short_month`, `add_month_numbers`, `prompt`), write tests for them, and otherwise support them
      # @todo Could we take the rendering from Rails' helpers and inject better HTML in and around it rather than re-inventing the whee?
      module Timeish
        
        def to_html
          input_wrapping do
            fragments_wrapping do
              hidden_fragments <<
              fragments_label <<
              template.content_tag(:ol,
                fragments.map do |fragment|
                  fragment_wrapping do
                    fragment_label_html(fragment) <<
                    fragment_input_html(fragment)
                  end
                end.join.html_safe, # TODO is this safe?
                { :class => 'fragments-group' } # TODO refactor to fragments_group_wrapping
              )
            end
          end
        end
        
        def fragments
          date_fragments + time_fragments
        end
        
        def time_fragments
          options[:include_seconds] ? [:hour, :minute, :second] : [:hour, :minute]
        end
        
        def date_fragments
          options[:order] || i18n_date_fragments || default_date_fragments
        end
        
        def default_date_fragments
          [:year, :month, :day]
        end
        
        def fragment_wrapping(&block)
          template.content_tag(:li, template.capture(&block), fragment_wrapping_html_options)
        end
        
        def fragment_wrapping_html_options
          { :class => 'fragment' }
        end
        
        def fragment_label(fragment)
          labels_from_options = options[:labels] || {}
          if labels_from_options.key?(fragment)
            labels_from_options[fragment]
          else
            ::I18n.t(fragment.to_s, :default => fragment.to_s.humanize, :scope => [:datetime, :prompts])
          end
        end
        
        def fragment_id(fragment)
          "#{input_html_options[:id]}_#{position(fragment)}i"
        end
        
        def fragment_name(fragment)
          "#{method}(#{position(fragment)}i)"
        end
        
        def fragment_label_html(fragment)
          text = fragment_label(fragment)
          text.blank? ? "".html_safe : template.content_tag(:label, text, :for => fragment_id(fragment))
        end
        
        def value
          object.send(method) if object && object.respond_to?(method)
        end
        
        def fragment_input_html(fragment)
          opts = input_options.merge(:prefix => fragment_prefix, :field_name => fragment_name(fragment), :default => value, :include_blank => include_blank?)
          template.send(:"select_#{fragment}", value, opts, input_html_options.merge(:id => fragment_id(fragment)))
        end
        
        def fragment_prefix
          if builder.options.key?(:index)
            object_name + "[#{builder.options[:index]}]"
          else
            object_name
          end
        end
        
        # TODO extract to BlankOptions or similar -- Select uses similar code
        def include_blank?
          options.key?(:include_blank) ? options[:include_blank] : builder.include_blank_for_select_by_default
        end
        
        def positions
          { :year => 1, :month => 2, :day => 3, :hour => 4, :minute => 5, :second => 6 }
        end
        
        def position(fragment)
          positions[fragment]
        end
        
        def i18n_date_fragments
          order = ::I18n.t(:order, :scope => [:date])
          order = nil unless order.is_a?(Array)
          order
        end
        
        def fragments_wrapping(&block)
          template.content_tag(:fieldset,
            template.capture(&block).html_safe, 
            fragments_wrapping_html_options
          )
        end
        
        def fragments_wrapping_html_options
          { :class => "fragments" }
        end
        
        def fragments_label
          if render_label?
            template.content_tag(:legend, 
              builder.label(method, label_text, :for => fragment_id(fragments.first)), 
              :class => "label"
            )
          else
            "".html_safe
          end
        end
        
        def fragments_inner_wrapping(&block)
          template.content_tag(:ol,
            template.capture(&block)
          )
        end
        
        def hidden_fragments
          "".html_safe
        end
        
        def hidden_field_name(fragment)
          if builder.options.key?(:index)
            "#{object_name}[#{builder.options[:index]}][#{fragment_name(fragment)}]"
          else
            "#{object_name}[#{fragment_name(fragment)}]"
          end
        end
        
      end
    end
  end
end
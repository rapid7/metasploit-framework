###
### $Release: 2.7.0 $
### copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
###


module Erubis
  module Helpers
    module RailsFormHelper
    end
  end
end


module Erubis::Helpers::RailsFormHelper


if ActionPack::VERSION::MAJOR == 1   ###  Rails 1.X
  def pp_template_filename(basename)
    return "#{RAILS_ROOT}/app/views/#{controller.controller_name}/#{basename}.rhtml"
  end
else                                 ###  Rails 2.X
  def pp_template_filename(basename)
    fname = "#{RAILS_ROOT}/app/views/#{controller.controller_name}/#{basename}.html.erb"
    return fname if test(?f, fname)
    return  "#{RAILS_ROOT}/app/views/#{controller.controller_name}/#{basename}.rhtml"
  end
end

  def pp_render_partial(basename)
    basename = "_#{basename}" unless basename[0] == ?_
    filename = pp_template_filename(basename)
    preprocessor = _create_preprocessor(File.read(filename))
    return preprocessor.evaluate(_preprocessing_context_object())
  end

  def pp_error_on(object_name, method)
    s = ''
    s << "<% _stag, _etag = _pp_error_tags(@#{object_name}.errors.on('#{method}')) %>"
    s << "<%= _stag %>"
    s << yield(object_name, method)
    s << "<%= _etag %>"
    return s
  end

  def _pp_error_tags(value)
    return value ? ['<div class="fieldWithErrors">', '</div>'] : ['', '']
  end

  def _pp_remove_error_div(s)
    s.sub!(/\A<div class="fieldWithErrors">(.*)<\/div>\z/, '\1')
    return s
  end

  def pp_tag_helper(helper, object_name, method, options={})
    if object_name.is_a?(ActionView::Helpers::FormHelper)
      object_name = object_name.object_name
    end
    unless options.key?(:value) || options.key?('value')
      options['value'] = _?("h @#{object_name}.#{method}")
    end
    #$stderr.puts "*** debug: pp_tag_helper(): options=#{options.inspect}"
    return pp_error_on(object_name, method) {
      s = __send__(helper, object_name, method, options)
      _pp_remove_error_div(s)
    }
  end

  def pp_form_tag(url_for_options={}, options={}, *parameters_for_url, &block)
    return form_tag(url_for_options, options, *parameters_for_url, &block)
  end

  #--
  #def pp_form_for(object_name, *args, &block)
  #  return form_for(object_name, *args, &block)
  #end
  #++

  def pp_text_field(object_name, method, options={})
    return pp_tag_helper(:text_field, object_name, method, options)
  end

  def pp_password_field(object_name, method, options={})
    return pp_tag_helper(:password_field, object_name, method, options)
  end

  def pp_hidden_field(object_name, method, options={})
    return pp_tag_helper(:hidden_field, object_name, method, options)
  end

  def pp_file_field(object_name, method, options={})
    return pp_tag_helper(:file_field, object_name, method, options)
  end

  def pp_text_area(object_name, method, options={})
    return pp_tag_helper(:text_area, object_name, method, options)
  end

  def pp_check_box(object_name, method, options={}, checked_value="1", unchecked_value="0")
    s = check_box(object_name, method, options, checked_value, unchecked_value)
    s.sub!(/\schecked=\"checked\"/, '')
    s.sub!(/type="checkbox"/, "\\&<%= _pp_check_box_checked?(@#{object_name}.#{method}, #{checked_value.inspect}) ? ' checked=\"checked\"' : '' %>")
    return pp_error_on(object_name, method) { _pp_remove_error_div(s) }
  end

  def _pp_check_box_checked?(value, checked_value)
    return ActionView::Helpers::InstanceTag::check_box_checked?(value, checked_value)
  end

  def pp_radio_button(object_name, method, tag_value, options={})
    s = radio_button(object_name, method, tag_value, options)
    s.sub!(/\schecked=\"checked\"/, '')
    s.sub!(/type="radio"/, "\\&<%= _pp_radio_button_checked?(@#{object_name}.#{method}, #{tag_value.inspect}) ? ' checked=\"checked\"' : '' %>")
    return pp_error_on(object_name, method) { _pp_remove_error_div(s) }
  end

  def _pp_radio_button_checked?(value, tag_value)
    return ActionView::Helpers::InstanceTag::radio_button_checked?(value, tag_value)
  end

  def _pp_select(object, method, collection, priority_collection, options={}, html_options={})
    return pp_error_on(object, method) do
      s = ""
      ## start tag
      s << "<select id=\"#{object}_#{method}\" name=\"#{object}[#{method}]\""
      for key, val in html_options:
          s << " #{key}=\"#{val}\""
      end
      s << ">\n"
      ## selected table
      key = options.key?(:value) ? :value : (options.key?('value') ? 'value' : nil)
      if    key.nil?                ;  selected = "@#{object}.#{method}"
      elsif (val=options[key]).nil? ;  selected = nil
      elsif val =~ /\A<%=(.*)%>\z/  ;  selected = $1
      else                          ;  selected = val.inspect
      end
      s << "<% _table = {#{selected}=>' selected=\"selected\"'} %>\n" if selected
      ## <option> tags
      if options[:include_blank] || options['include_blank']
        s << "<option value=\"\"></option>\n"
      end
      unless priority_collection.blank?
        _pp_select_options(s, priority_collection, selected, 'delete')
        s << "<option value=\"\">-------------</option>\n"
      end
      _pp_select_options(s, collection, selected, '[]')
      ## end tag
      s << "</select>"
      s
    end
  end

  def _pp_select_options(s, collection, selected, operator)
    for item in collection
      value, text = item.is_a?(Array) ? item : [item, item]
      if !selected
        t = ''
      elsif operator == 'delete'
        t = "<%= _table.delete(#{value.inspect}) %>"
      else
        t = "<%= _table[#{value.inspect}] %>"
      end
      s << "<option value=\"#{h value}\"#{t}>#{h text}</option>\n"
    end
  end

  def pp_select(object, method, collection, options={}, html_options={})
    return _pp_select(object, method, collection, nil, options, html_options)
  end

  def pp_collection_select(object, method, collection, value_method, text_method, options={}, html_options={})
    collection2 = collection.collect { |e|
      [e.__send__(value_method), e.__send__(text_method)]
    }
    return _pp_select(object, method, collection2, nil, options, html_options)
  end

  def pp_country_select(object, method, priority_countries=nil, options={}, html_options={})
    collection = ActionView::Helpers::FormOptionsHelper::COUNTRIES
    return _pp_select(object, method, collection, priority_countries, options, html_options)
  end

  def pp_time_zone_select(object, method, priority_zones=nil, options={}, html_options={})
    model = options[:model] || options['model'] || TimeZone
    collection = model.all.collect { |e| [e.name, e.to_s] }
    return _pp_select(object, method, collection, priority_zones, options, html_options)
  end

  def pp_submit_tag(value="Save changes", options={})
    return submit_tag(value, options)
  end

  def pp_image_submit_tag(source, options={})
    return image_submit_tag(source, options)
  end

end

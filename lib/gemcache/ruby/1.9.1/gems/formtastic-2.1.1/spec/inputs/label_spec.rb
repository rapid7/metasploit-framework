# encoding: utf-8
require 'spec_helper'

describe 'Formtastic::FormBuilder#label' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
  end

  it 'should add "required string" only once with caching enabled' do
    with_config :i18n_cache_lookups, true do
      ::I18n.backend.store_translations :en, { :formtastic => { :labels => { :post => { :title => "I18n title" } } } }
      required_string = "[req_string]"
      default_required_str = Formtastic::FormBuilder.required_string
      Formtastic::FormBuilder.required_string = required_string

      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :required => true, :label => true)
      end)
      output_buffer.replace ''
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :required => true, :label => true)
      end)

      ::I18n.backend.store_translations :en, { :formtastic => { :labels => { :post => { :title => nil } } } }
      Formtastic::FormBuilder.required_string = default_required_str

      output_buffer.scan(required_string).count.should == 1
    end
  end

  it 'should humanize the given attribute' do
    concat(semantic_form_for(@new_post) do |builder|
      builder.input(:title)
    end)
    output_buffer.should have_tag('label', /Title/)
  end

  it 'should humanize the given attribute for date fields' do
    concat(semantic_form_for(@new_post) do |builder|
      builder.input(:publish_at)
    end)
    output_buffer.should have_tag('label', /Publish at/)
  end

  describe 'when required is given' do
    it 'should append a required note' do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :required => true)
      end)
      output_buffer.should have_tag('label abbr', '*')
    end
  end

  describe 'when a collection is given' do
    it 'should use a supplied label_method for simple collections' do
      concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
        concat(builder.input(:author_id, :as => :check_boxes, :collection => [:a, :b, :c], :member_value => :to_s, :member_label => proc {|f| ('Label_%s' % [f])}))
      end)
      output_buffer.should have_tag('form li fieldset ol li label', /Label_[abc]/, :count => 3)
    end

    it 'should use a supplied value_method for simple collections' do
      concat(semantic_form_for(:project, :url => 'http://test.host') do |builder|
        concat(builder.input(:author_id, :as => :check_boxes, :collection => [:a, :b, :c], :member_value => proc {|f| ('Value_%s' % [f.to_s])}))
      end)
      output_buffer.should have_tag('form li fieldset ol li label input[value="Value_a"]')
      output_buffer.should have_tag('form li fieldset ol li label input[value="Value_b"]')
      output_buffer.should have_tag('form li fieldset ol li label input[value="Value_c"]')
    end
  end

  describe 'when label is given' do
    it 'should allow the text to be given as label option' do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :label => 'My label')
      end)
      output_buffer.should have_tag('label', /My label/)
    end
    
    it 'should allow the text to be given as label option for date fields' do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:publish_at, :label => 'My other label')
      end)
      output_buffer.should have_tag('label', /My other label/)
    end

    it 'should return nil if label is false' do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :label => false)
      end)
      output_buffer.should_not have_tag('label')
      output_buffer.should_not include("&gt;")
    end
    
    it 'should return nil if label is false for timeish fragments' do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :as => :time, :label => false)
      end)
      output_buffer.should_not have_tag('li.time > label')
      output_buffer.should_not include("&gt;")
    end

    it 'should html escape the label string by default' do
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :label => '<b>My label</b>')
      end)
      output_buffer.should include('&lt;b&gt;')
      output_buffer.should_not include('<b>')
    end

    it 'should not html escape the label if configured that way' do
      Formtastic::FormBuilder.escape_html_entities_in_hints_and_labels = false
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :label => '<b>My label</b>')
      end)
      output_buffer.should have_tag("label b", "My label")
    end

    it 'should not html escape the label string for html_safe strings' do
      Formtastic::FormBuilder.escape_html_entities_in_hints_and_labels = true
      concat(semantic_form_for(@new_post) do |builder|
        builder.input(:title, :label => '<b>My label</b>'.html_safe)
      end)
      output_buffer.should have_tag('label b')
    end

  end

end


# encoding: utf-8
require 'spec_helper'

describe 'country input' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
  end

  describe "when country_select is not available as a helper from a plugin" do

    it "should raise an error, sugesting the author installs a plugin" do
      lambda {
        semantic_form_for(@new_post) do |builder|
          concat(builder.input(:country, :as => :country))
        end
      }.should raise_error
    end

  end

  describe "when country_select is available as a helper (from a plugin)" do

    before do
      concat(semantic_form_for(@new_post) do |builder|
        builder.stub!(:country_select).and_return(Formtastic::Util.html_safe("<select><option>...</option></select>"))
        concat(builder.input(:country, :as => :country))
      end)
    end

    it_should_have_input_wrapper_with_class("country")
    it_should_have_input_wrapper_with_class(:input)
    it_should_have_input_wrapper_with_id("post_country_input")

    # TODO -- needs stubbing inside the builder block, tricky!
    #it_should_apply_error_logic_for_input_type(:country)

    it 'should generate a label for the input' do
      output_buffer.should have_tag('form li label')
      output_buffer.should have_tag('form li label[@for="post_country"]')
      output_buffer.should have_tag('form li label', /Country/)
    end

    it "should generate a select" do
      output_buffer.should have_tag("form li select")
    end

  end

  describe ":priority_countries option" do

    it "should be passed down to the country_select helper when provided" do
      priority_countries = ["Foo", "Bah"]
      semantic_form_for(@new_post) do |builder|
        builder.stub!(:country_select).and_return(Formtastic::Util.html_safe("<select><option>...</option></select>"))
        builder.should_receive(:country_select).with(:country, priority_countries, {}, {:id => "post_country", :required => false, :autofocus => false}).and_return(Formtastic::Util.html_safe("<select><option>...</option></select>"))

        concat(builder.input(:country, :as => :country, :priority_countries => priority_countries))
      end
    end

    it "should default to the @@priority_countries config when absent" do
      priority_countries = Formtastic::FormBuilder.priority_countries
      priority_countries.should_not be_empty
      priority_countries.should_not be_nil

      semantic_form_for(@new_post) do |builder|
        builder.stub!(:country_select).and_return(Formtastic::Util.html_safe("<select><option>...</option></select>"))
        builder.should_receive(:country_select).with(:country, priority_countries, {}, {:id => "post_country", :required => false, :autofocus => false}).and_return(Formtastic::Util.html_safe("<select><option>...</option></select>"))

        concat(builder.input(:country, :as => :country))
      end
    end

  end

  describe "when namespace is provided" do

    before do
      @output_buffer = ''
      mock_everything

      concat(semantic_form_for(@new_post, :namespace => 'context2') do |builder|
        builder.stub!(:country_select).and_return(Formtastic::Util.html_safe("<select><option>...</option></select>"))
        builder.should_receive(:country_select).with(:country, [], {}, {:id => "context2_post_country", :required => false, :autofocus => false}).and_return(Formtastic::Util.html_safe("<select><option>...</option></select>"))
        concat(builder.input(:country, :priority_countries => []))
      end)
    end

    it_should_have_input_wrapper_with_id("context2_post_country_input")
    it_should_have_label_for("context2_post_country")

  end

  describe "matching" do

    describe "when the attribute is 'country'" do

      before do
        concat(semantic_form_for(@new_post) do |builder|
          builder.stub!(:country_select).and_return(Formtastic::Util.html_safe("<select><option>...</option></select>"))
          concat(builder.input(:country))
        end)
      end

      it "should render a country input" do
        output_buffer.should have_tag "form li.country"
      end
    end

    describe "whent the attribute is 'country_something'" do

      before do
        concat(semantic_form_for(@new_post) do |builder|
          concat(builder.input(:country_subdivision))
          concat(builder.input(:country_code))
        end)
      end

      it "should render a country input" do
        output_buffer.should_not have_tag "form li.country"
        output_buffer.should have_tag "form li.string", :count => 2
      end

    end

  end

end


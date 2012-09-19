# encoding: utf-8
require 'spec_helper'

describe 'Formtastic::FormBuilder#buttons' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
  end

  describe 'with a block' do
    describe 'when no options are provided' do
      before do
        with_deprecation_silenced do
          concat(semantic_form_for(@new_post) do |builder|
            buttons = builder.buttons do
              concat('hello')
            end
            concat(buttons)
          end)
        end
      end

      it 'should render a fieldset inside the form, with a class of "inputs"' do
        output_buffer.should have_tag("form fieldset.buttons")
      end

      it 'should render an ol inside the fieldset' do
        output_buffer.should have_tag("form fieldset.buttons ol")
      end

      it 'should render the contents of the block inside the ol' do
        output_buffer.should have_tag("form fieldset.buttons ol", /hello/)
      end

      it 'should not render a legend inside the fieldset' do
        output_buffer.should_not have_tag("form fieldset.buttons legend")
      end
    end

    describe 'when a :name option is provided' do
      before do
        @legend_text = "Advanced options"

        with_deprecation_silenced do
          concat(semantic_form_for(@new_post) do |builder|
            builder.buttons :name => @legend_text do
            end
          end)
        end
      end
      
      it 'should render a fieldset inside the form' do
        output_buffer.should have_tag("form fieldset legend", /#{@legend_text}/)
      end

    end

    describe 'when other options are provided' do
      before do
        @id_option = 'advanced'
        @class_option = 'wide'

        with_deprecation_silenced do
          concat(semantic_form_for(@new_post) do |builder|
            builder.buttons :id => @id_option, :class => @class_option do
            end
          end)
        end
      end
      
      it 'should pass the options into the fieldset tag as attributes' do
        output_buffer.should have_tag("form fieldset##{@id_option}")
        output_buffer.should have_tag("form fieldset.#{@class_option}")
      end

    end

  end

  describe 'without a block' do

    describe 'with no args (default buttons)' do

      before do
        with_deprecation_silenced do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.buttons)
          end)
        end
      end

      it 'should render a form' do
        output_buffer.should have_tag('form')
      end

      it 'should render a buttons fieldset inside the form' do
        output_buffer.should have_tag('form fieldset.buttons')
      end

      it 'should not render a legend in the fieldset' do
        output_buffer.should_not have_tag('form fieldset.buttons legend')
      end

      it 'should render an ol in the fieldset' do
        output_buffer.should have_tag('form fieldset.buttons ol')
      end

      it 'should render a list item in the ol for each default button' do
        output_buffer.should have_tag('form fieldset.buttons ol li', :count => 1)
      end

      it 'should render a commit list item for the commit button' do
        output_buffer.should have_tag('form fieldset.buttons ol li.commit')
      end

    end

    describe 'with button names as args' do

      before do
        with_deprecation_silenced do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.buttons(:commit))
          end)
        end
      end

      it 'should render a form with a fieldset containing a list item for each button arg' do
        output_buffer.should have_tag('form > fieldset.buttons > ol > li', :count => 1)
        output_buffer.should have_tag('form > fieldset.buttons > ol > li.commit')
      end

    end

    describe 'with button names as args and an options hash' do

      before do
        with_deprecation_silenced do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.buttons(:commit, :name => "Now click a button", :id => "my-id"))
          end)
        end
      end

      it 'should render a form with a fieldset containing a list item for each button arg' do
        output_buffer.should have_tag('form > fieldset.buttons > ol > li', :count => 1)
        output_buffer.should have_tag('form > fieldset.buttons > ol > li.commit', :count => 1)
      end

      it 'should pass the options down to the fieldset' do
        output_buffer.should have_tag('form > fieldset#my-id.buttons')
      end

      it 'should use the special :name option as a text for the legend tag' do
        output_buffer.should have_tag('form > fieldset#my-id.buttons > legend', /Now click a button/)
      end

    end

  end

end


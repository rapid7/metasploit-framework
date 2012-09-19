# encoding: utf-8
require 'spec_helper'

describe "*select: options[:include_blank]" do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything

    @new_post.stub!(:author_id).and_return(nil)
    @new_post.stub!(:publish_at).and_return(nil)
  end

  SELECT_INPUT_TYPES = {
      :select => :author,
      :datetime => :publish_at,
      :date => :publish_at,
      :time => :publish_at
    }

  SELECT_INPUT_TYPES.each do |as, attribute|
    describe "for #{as} input" do

      describe 'when :include_blank is not set' do
        it 'blank value should be included if the default value specified in config is true' do
          Formtastic::FormBuilder.include_blank_for_select_by_default = true
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.input(attribute, :as => as))
          end)
          output_buffer.should have_tag("form li select option[@value='']", "")
        end

        it 'blank value should not be included if the default value specified in config is false' do
          Formtastic::FormBuilder.include_blank_for_select_by_default = false
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.input(attribute, :as => as))
          end)
          output_buffer.should_not have_tag("form li select option[@value='']", "")
        end

        after do
          Formtastic::FormBuilder.include_blank_for_select_by_default = true
        end
      end

      describe 'when :include_blank is set to false' do
        it 'should not have a blank option' do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.input(attribute, :as => as, :include_blank => false))
          end)
          output_buffer.should_not have_tag("form li select option[@value='']", "")
        end
      end

      describe 'when :include_blank is set to true' do
        it 'should have a blank select option' do
          concat(semantic_form_for(@new_post) do |builder|
            concat(builder.input(attribute, :as => as, :include_blank => true))
          end)
          output_buffer.should have_tag("form li select option[@value='']", "")
        end
      end

      if as == :select
        describe 'when :include_blank is set to a string' do
          it 'should have a select option with blank value but that string as text' do
            concat(semantic_form_for(@new_post) do |builder|
              concat(builder.input(attribute, :as => as, :include_blank => 'string'))
            end)
            output_buffer.should have_tag("form li select option[@value='']", "string")
          end
        end
      end
    end
  end
end

# encoding: utf-8
require 'spec_helper'

describe 'Formtastic::FormBuilder#semantic_errors' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
    @title_errors = ['must not be blank', 'must be awesome']
    @base_errors = ['base error message', 'nasty error']
    @base_error = 'one base error'
    @errors = mock('errors')
    @new_post.stub!(:errors).and_return(@errors)
  end

  describe 'when there is only one error on base' do
    before do
      @errors.stub!(:[]).with(:base).and_return(@base_error)
    end

    it 'should render an unordered list' do
      semantic_form_for(@new_post) do |builder|
        builder.semantic_errors.should have_tag('ul.errors li', @base_error)
      end
    end
  end

  describe 'when there is more than one error on base' do
    before do
      @errors.stub!(:[]).with(:base).and_return(@base_errors)
    end

    it 'should render an unordered list' do
      semantic_form_for(@new_post) do |builder|
        builder.semantic_errors.should have_tag('ul.errors')
        @base_errors.each do |error|
          builder.semantic_errors.should have_tag('ul.errors li', error)
        end
      end
    end
  end

  describe 'when there are errors on title' do
    before do
      @errors.stub!(:[]).with(:title).and_return(@title_errors)
      @errors.stub!(:[]).with(:base).and_return([])
    end

    it 'should render an unordered list' do
      semantic_form_for(@new_post) do |builder|
        title_name = builder.send(:localized_string, :title, :title, :label) || builder.send(:humanized_attribute_name, :title)
        builder.semantic_errors(:title).should have_tag('ul.errors li', title_name << " " << @title_errors.to_sentence)
      end
    end
  end

  describe 'when there are errors on title and base' do
    before do
      @errors.stub!(:[]).with(:title).and_return(@title_errors)
      @errors.stub!(:[]).with(:base).and_return(@base_error)
    end

    it 'should render an unordered list' do
      semantic_form_for(@new_post) do |builder|
        title_name = builder.send(:localized_string, :title, :title, :label) || builder.send(:humanized_attribute_name, :title)
        builder.semantic_errors(:title).should have_tag('ul.errors li', title_name << " " << @title_errors.to_sentence)
        builder.semantic_errors(:title).should have_tag('ul.errors li', @base_error)
      end
    end
  end

  describe 'when there are no errors' do
    before do
      @errors.stub!(:[]).with(:title).and_return(nil)
      @errors.stub!(:[]).with(:base).and_return(nil)
    end

    it 'should return nil' do
      semantic_form_for(@new_post) do |builder|
        builder.semantic_errors(:title).should be_nil
      end
    end
  end

  describe 'when there is one error on base and options with class is passed' do
    before do
      @errors.stub!(:[]).with(:base).and_return(@base_error)
    end

    it 'should render an unordered list with given class' do
      semantic_form_for(@new_post) do |builder|
        builder.semantic_errors(:class => "awesome").should have_tag('ul.awesome li', @base_error)
      end
    end
  end
  
  describe 'when :base is passed in as an argument' do
    before do
      @errors.stub!(:[]).with(:base).and_return(@base_error)
    end

    it 'should ignore :base and only render base errors once' do
      semantic_form_for(@new_post) do |builder|
        builder.semantic_errors(:base).should have_tag('ul li', :count => 1)
        builder.semantic_errors(:base).should_not have_tag('ul li', "Base #{@base_error}")
      end
    end
  end
  
end

# encoding: utf-8
require 'spec_helper'

describe 'LinkAction', 'when cancelling' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
  end
  
  context 'without a :url' do
    before do
      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.action(:cancel, :as => :link))
      end)
    end
    
    it 'should render a submit type of input' do
      output_buffer.should have_tag('li.action.link_action a[@href="javascript:history.back()"]')
    end
    
  end
  
  context 'with a :url as String' do
    
    before do
      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.action(:cancel, :as => :link, :url => "http://foo.bah/baz"))
      end)
    end
    
    it 'should render a submit type of input' do
      output_buffer.should have_tag('li.action.link_action a[@href="http://foo.bah/baz"]')
    end
    
  end

  context 'with a :url as Hash' do
    
    before do
      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.action(:cancel, :as => :link, :url => { :action => "foo" }))
      end)
    end
    
    it 'should render a submit type of input' do
      output_buffer.should have_tag('li.action.link_action a[@href="/mock/path"]')
    end
    
  end

end

describe 'LinkAction', 'when submitting' do

  include FormtasticSpecHelper
  
  before do
    @output_buffer = ''
    mock_everything
  end
  
  it 'should raise an error' do
    lambda { 
      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.action(:submit, :as => :link))
      end)
    }.should raise_error(Formtastic::UnsupportedMethodForAction)
  end
  
end

describe 'LinkAction', 'when submitting' do

  include FormtasticSpecHelper
  
  before do
    @output_buffer = ''
    mock_everything
  end
  
  it 'should raise an error' do
    lambda { 
      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.action(:reset, :as => :link))
      end)
    }.should raise_error(Formtastic::UnsupportedMethodForAction)
  end
  
end
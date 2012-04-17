# encoding: utf-8
require 'spec_helper'

describe 'InputAction', 'when submitting' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
    
    concat(semantic_form_for(@new_post) do |builder|
      concat(builder.action(:submit, :as => :input))
    end)
  end
  
  it 'should render a submit type of input' do
    output_buffer.should have_tag('li.action.input_action input[@type="submit"]')
  end

end

describe 'InputAction', 'when resetting' do

  include FormtasticSpecHelper
  
  before do
    @output_buffer = ''
    mock_everything
    
    concat(semantic_form_for(@new_post) do |builder|
      concat(builder.action(:reset, :as => :input))
    end)
  end
  
  it 'should render a reset type of input' do
    output_buffer.should have_tag('li.action.input_action input[@type="reset"]')
  end
  
end

describe 'InputAction', 'when cancelling' do

  include FormtasticSpecHelper
  
  before do
    @output_buffer = ''
    mock_everything
  end
  
  it 'should raise an error' do
    lambda { 
      concat(semantic_form_for(@new_post) do |builder|
        concat(builder.action(:cancel, :as => :input))
      end)
    }.should raise_error(Formtastic::UnsupportedMethodForAction)
  end
  
end
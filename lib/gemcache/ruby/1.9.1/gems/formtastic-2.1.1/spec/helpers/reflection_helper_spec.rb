# encoding: utf-8
require 'spec_helper'

describe 'Formtastic::Helpers::Reflection' do

  include FormtasticSpecHelper

  before do
    @output_buffer = ''
    mock_everything
  end

  class ReflectionTester
    include Formtastic::Helpers::Reflection
    def initialize(model_object)
      @object = model_object
    end
  end

  context 'with an ActiveRecord object' do
    it "should return association details on an ActiveRecord association" do
      @reflection_tester = ReflectionTester.new(@new_post)
      @reflection_tester.reflection_for(:sub_posts).should_not be_nil
    end
    it "should return association details on a MongoMapper association" do
      @reflection_tester = ReflectionTester.new(@new_mm_post)
      @reflection_tester.reflection_for(:sub_posts).should_not be_nil
    end
  end
  
  
end
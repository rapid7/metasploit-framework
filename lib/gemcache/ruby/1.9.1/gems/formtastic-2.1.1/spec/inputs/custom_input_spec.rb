# encoding: utf-8
require 'spec_helper'

# TODO extract out
module TestInputs

  def input_args
    @template = self
    @object = ::Post.new
    @object_name = 'post'
    @method = :title
    @options = {}
    @proc = Proc.new {}
    @builder = Formtastic::FormBuilder.new(@object_name, @object, @template, @options, @proc)
    
    [@builder, @template, @object, @object_name, @method, @options]
  end
  
  class ::UnimplementedInput
    include Formtastic::Inputs::Base
  end

  class ::ImplementedInput < UnimplementedInput
    def to_html
      "some HTML output"
    end
  end
  
end

describe 'AnyCustomInput' do
  
  include TestInputs
  
  describe "#to_html" do

    describe 'without an implementation' do
      it "should raise a NotImplementedError exception" do
        expect { ::UnimplementedInput.new(*input_args).to_html }.to raise_error(NotImplementedError)
      end
    end    

    describe 'with an implementation' do
      it "should raise a NotImplementedError exception" do
        expect { ::ImplementedInput.new(*input_args).to_html }.to_not raise_error(NotImplementedError)
      end
    end
    
  end
    
end


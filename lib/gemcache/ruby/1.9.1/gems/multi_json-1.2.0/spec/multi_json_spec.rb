require 'helper'
require 'engine_shared_example'
require 'stringio'

describe 'MultiJson' do
  context 'engines' do
    before do
      MultiJson.engine = nil
    end
    context 'when no other json implementations are available' do
      before do
        @old_map = MultiJson::REQUIREMENT_MAP
        @old_json = Object.const_get :JSON if Object.const_defined?(:JSON)
        @old_oj = Object.const_get :Oj if Object.const_defined?(:Oj)
        @old_yajl = Object.const_get :Yajl if Object.const_defined?(:Yajl)
        MultiJson::REQUIREMENT_MAP.each_with_index do |(library, engine), index|
          MultiJson::REQUIREMENT_MAP[index] = ["foo/#{library}", engine]
        end
        Object.send :remove_const, :JSON if @old_json
        Object.send :remove_const, :Oj if @old_oj
        Object.send :remove_const, :Yajl if @old_yajl
      end

      after do
        @old_map.each_with_index do |(library, engine), index|
          MultiJson::REQUIREMENT_MAP[index] = [library, engine]
        end
        Object.const_set :JSON, @old_json if @old_json
        Object.const_set :Oj, @old_oj if @old_oj
        Object.const_set :Yajl, @old_yajl if @old_yajl
      end

      it 'defaults to ok_json if no other json implementions are available' do
        MultiJson.default_engine.should == :ok_json
      end

      it 'prints a warning' do
        Kernel.should_receive(:warn).with(/warning/i)
        MultiJson.default_engine
      end
    end

    it 'defaults to the best available gem' do
      unless jruby?
        require 'oj'
        MultiJson.engine.name.should == 'MultiJson::Engines::Oj'
      else
        require 'json'
        MultiJson.engine.name.should == 'MultiJson::Engines::JsonGem'
      end
    end

    it 'is settable via a symbol' do
      MultiJson.engine = :json_gem
      MultiJson.engine.name.should == 'MultiJson::Engines::JsonGem'
    end

    it 'is settable via a class' do
      MultiJson.engine = MockDecoder
      MultiJson.engine.name.should == 'MockDecoder'
    end
  end

  %w(json_gem json_pure nsjsonserialization oj ok_json yajl).each do |engine|
    next if !macruby? && engine == 'nsjsonserialization'
    next if jruby? && (engine == 'oj' || engine == 'yajl')

    context engine do
      it_should_behave_like "an engine", engine
    end
  end
end

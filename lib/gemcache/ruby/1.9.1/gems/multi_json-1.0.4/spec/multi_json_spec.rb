require 'helper'
require 'stringio'

describe "MultiJson" do
  context 'engines' do
    context 'when no other json implementations are available' do
      before(:each) do
        @old_map = MultiJson::REQUIREMENT_MAP
        @old_yajl = Object.const_get :Yajl if Object.const_defined?(:Yajl)
        @old_json = Object.const_get :JSON if Object.const_defined?(:JSON)
        MultiJson::REQUIREMENT_MAP.each_with_index do |(library, engine), index|
          MultiJson::REQUIREMENT_MAP[index] = ["foo/#{library}", engine]
        end
        Object.send :remove_const, :Yajl if @old_yajl
        Object.send :remove_const, :JSON if @old_json
      end

      after(:each) do
        @old_map.each_with_index do |(library, engine), index|
          MultiJson::REQUIREMENT_MAP[index] = [library, engine]
        end
        Object.const_set :Yajl, @old_yajl if @old_yajl
        Object.const_set :JSON, @old_json if @old_json
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
        require 'yajl'
        MultiJson.engine.name.should == 'MultiJson::Engines::Yajl'
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

  %w(json_gem json_pure ok_json yajl).each do |engine|
    if yajl_on_travis(engine)
      puts "Yajl with JRuby is not tested on Travis as C-exts are turned off due to there experimental nature"
      next
    end

    context engine do
      before do
        begin
          MultiJson.engine = engine
        rescue LoadError
          pending "Engine #{engine} couldn't be loaded (not installed?)"
        end
      end

      describe '.encode' do
        it 'writes decodable JSON' do
          [
            { 'abc' => 'def' },
            [1, 2, 3, "4"]
          ].each do |example|
            MultiJson.decode(MultiJson.encode(example)).should == example
          end
        end

        it 'encodes symbol keys as strings' do
          [
            [
              { :foo => { :bar => 'baz' } },
              { 'foo' => { 'bar' => 'baz' } }
            ],
            [
              [ { :foo => { :bar => 'baz' } } ],
              [ { 'foo' => { 'bar' => 'baz' } } ],
            ],
            [
              { :foo => [ { :bar => 'baz' } ] },
              { 'foo' => [ { 'bar' => 'baz' } ] },
            ]
          ].each do |example, expected|
            encoded_json = MultiJson.encode(example)
            MultiJson.decode(encoded_json).should == expected
          end
        end

        it 'encodes rootless JSON' do
          MultiJson.encode("random rootless string").should == "\"random rootless string\""
          MultiJson.encode(123).should == "123"
        end

        it 'passes options to the engine' do
          MultiJson.engine.should_receive(:encode).with('foo', {:bar => :baz})
          MultiJson.encode('foo', :bar => :baz)
        end

        if engine == 'json_gem' || engine == 'json_pure'
          describe 'with :pretty option set to true' do
            it 'passes default pretty options' do
              object = 'foo'
              object.should_receive(:to_json).with(JSON::PRETTY_STATE_PROTOTYPE.to_h)
              MultiJson.encode(object,:pretty => true)
            end
          end
        end

        it "encodes custom objects which implement as_json" do
          MultiJson.encode(TimeWithZone.new).should == "\"2005-02-01T15:15:10Z\""
        end
      end

      describe '.decode' do
        it 'properly decodes valid JSON' do
          MultiJson.decode('{"abc":"def"}').should == { 'abc' => 'def' }
        end

        it 'raises MultiJson::DecodeError on invalid JSON' do
          lambda do
            MultiJson.decode('{"abc"}')
          end.should raise_error(MultiJson::DecodeError)
        end

        it 'raises MultiJson::DecodeError with data on invalid JSON' do
          data = '{invalid}'
          begin
            MultiJson.decode(data)
          rescue MultiJson::DecodeError => de
            de.data.should == data
          end
        end

        it 'stringifys symbol keys when encoding' do
          encoded_json = MultiJson.encode(:a => 1, :b => {:c => 2})
          MultiJson.decode(encoded_json).should == { "a" => 1, "b" => { "c" => 2 } }
        end

        it "properly decodes valid JSON in StringIOs" do
          json = StringIO.new('{"abc":"def"}')
          MultiJson.decode(json).should == { 'abc' => 'def' }
        end

        it 'allows for symbolization of keys' do
          [
            [
              '{"abc":{"def":"hgi"}}',
              { :abc => { :def => 'hgi' } }
            ],
            [
              '[{"abc":{"def":"hgi"}}]',
              [ { :abc => { :def => 'hgi' } } ]
            ],
            [
              '{"abc":[{"def":"hgi"}]}',
              { :abc => [ { :def => 'hgi' } ] }
            ],
          ].each do |example, expected|
            MultiJson.decode(example, :symbolize_keys => true).should == expected
          end
        end
      end
    end
  end
end

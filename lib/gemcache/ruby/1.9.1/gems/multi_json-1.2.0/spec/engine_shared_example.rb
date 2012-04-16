shared_examples_for "an engine" do |engine|

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
        {'abc' => 'def'},
        [1, 2, 3, "4"],
      ].each do |example|
        MultiJson.decode(MultiJson.encode(example)).should == example
      end
    end

    it 'encodes symbol keys as strings' do
      [
        [
          {:foo => {:bar => 'baz'}},
          {'foo' => {'bar' => 'baz'}},
        ],
        [
          [{:foo => {:bar => 'baz'}}],
          [{'foo' => {'bar' => 'baz'}}],
        ],
        [
          {:foo => [{:bar => 'baz'}]},
          {'foo' => [{'bar' => 'baz'}]},
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
      MultiJson.decode('{"abc":"def"}').should == {'abc' => 'def'}
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
      MultiJson.decode(encoded_json).should == {"a" => 1, "b" => {"c" => 2}}
    end

    it "properly decodes valid JSON in StringIOs" do
      json = StringIO.new('{"abc":"def"}')
      MultiJson.decode(json).should == {'abc' => 'def'}
    end

    it 'allows for symbolization of keys' do
      [
        [
          '{"abc":{"def":"hgi"}}',
          {:abc => {:def => 'hgi'}},
        ],
        [
          '[{"abc":{"def":"hgi"}}]',
          [{:abc => {:def => 'hgi'}}],
        ],
        [
          '{"abc":[{"def":"hgi"}]}',
          {:abc => [{:def => 'hgi'}]},
        ],
      ].each do |example, expected|
        MultiJson.decode(example, :symbolize_keys => true).should == expected
      end
    end
  end
end

require "spec_helper"

describe MetasploitDataModels::Base64Serializer do
  let(:base64_marshaled) do
    marshaled = Marshal.dump(unserialized)

    [
        marshaled
    ].pack('m')
  end

  let(:default) do
    {}
  end

  let(:unserialized) do
    {
        :foo => 'bar',
        :baz => 'baz'
    }
  end

  let(:yaml) do
    unserialized.to_yaml
  end

  subject(:base64_serializer) do
    described_class.new
  end

  context 'CONSTANTS' do
    it 'should define DEFAULT' do
      described_class::DEFAULT.should == default
    end

    context 'LOADERS' do
      it 'should prefer base64 marshaled first' do
        first = described_class::LOADERS[0]
        deserialized = first.call(base64_marshaled)

        deserialized.should == unserialized
      end

      it 'should fallback to the old YAML format second' do
        second = described_class::LOADERS[1]
        deserialized = second.call(yaml)

        deserialized.should == unserialized
      end

      it 'should finally give up and just return the value' do
        last = described_class::LOADERS.last
        deserialized = last.call(unserialized)

        deserialized.should == unserialized
      end
    end
  end

  context '#default' do
    it 'should default to {}' do
      base64_serializer.default.should == {}
    end

    it 'should return a duplicate' do
      duplicate = base64_serializer.default
      value = mock('Value')
      duplicate[:key] = value

      duplicate.should_not == base64_serializer.default
    end
  end

  context '#dump' do
    it 'should output Base64 encoded marshaled data' do
      dumped = base64_serializer.dump(unserialized)

      dumped.should == base64_marshaled
    end
  end

  context '#initialize' do
    let(:attributes) do
      {}
    end

    subject(:base64_serializer) do
      described_class.new(attributes)
    end

    context 'with :default' do
      let(:attributes) do
        {
            :default => default
        }
      end

      let(:default) do
        [
            [
                'param',
                'value'
            ]
        ]
      end

      it 'should have :default in attributes' do
        attributes.should have_key(:default)
      end

      it 'should set default to :default value' do
        base64_serializer.default.should == attributes[:default]
      end
    end

    context 'without :default' do
      it 'should not have :default in attributes' do
        attributes.should_not have_key(:default)
      end

      it 'should default #default to DEFAULT' do
        base64_serializer.default.should == default
      end
    end
  end

  context '#load' do
    context 'with nil' do
      let(:serialized) do
        nil
      end

      it 'should return #default' do
        default = mock('Default')
        base64_serializer.stub(:default => default)
        deserialized = base64_serializer.load(serialized)

        deserialized.should == default
      end
    end

    context 'with Base64 encoded marshaled' do
      it 'should return unserialized' do
        deserialized = base64_serializer.load(base64_marshaled)

        deserialized.should == unserialized
      end

    end

    context 'with YAML' do
      it 'should return unserialized' do
        deserialized = base64_serializer.load(yaml)

        deserialized.should == unserialized
      end
    end

    context 'without Base64 encoded marshaled' do
      context 'without YAML' do
        let(:raw_value) do
          "< a > b >"
        end

        it 'should return raw value' do
          deserialized = base64_serializer.load(raw_value)

          deserialized.should == raw_value
        end
      end
    end
  end
end


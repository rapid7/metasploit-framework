# frozen_string_literal: true

require 'spec_helper'
require 'msf/core/db_manager/import/marshal_validator'

RSpec.describe Msf::DBManager::Import::MarshalValidator do
  let(:validation_error) { Msf::DBManager::Import::MarshalValidationError }

  describe '.safe_load' do
    context 'with safe primitive types' do
      it 'loads nil' do
        expect(described_class.safe_load(Marshal.dump(nil))).to be_nil
      end

      it 'loads true' do
        expect(described_class.safe_load(Marshal.dump(true))).to eq true
      end

      it 'loads false' do
        expect(described_class.safe_load(Marshal.dump(false))).to eq false
      end

      it 'loads a small positive integer' do
        expect(described_class.safe_load(Marshal.dump(42))).to eq 42
      end

      it 'loads zero' do
        expect(described_class.safe_load(Marshal.dump(0))).to eq 0
      end

      it 'loads a negative integer' do
        expect(described_class.safe_load(Marshal.dump(-7))).to eq(-7)
      end

      it 'loads a large integer (Bignum)' do
        big = 2**64
        expect(described_class.safe_load(Marshal.dump(big))).to eq big
      end

      it 'loads a float' do
        expect(described_class.safe_load(Marshal.dump(3.14))).to eq 3.14
      end

      it 'loads a symbol' do
        expect(described_class.safe_load(Marshal.dump(:hello))).to eq :hello
      end

      it 'loads a string' do
        expect(described_class.safe_load(Marshal.dump('hello'))).to eq 'hello'
      end

      it 'loads a string containing bytes that match unsafe type indicators' do
        expect(described_class.safe_load(Marshal.dump('object class module'))).to eq 'object class module'
      end
    end

    context 'with permitted _dump/_load classes' do
      it 'loads a Time instance when Time is permitted' do
        time = Time.new(2025, 6, 15, 12, 30, 0, '+00:00')
        result = described_class.safe_load(Marshal.dump(time), permitted_classes: %w[Time])
        expect(result).to be_a(Time)
        expect(result.to_i).to eq time.to_i
      end

      it 'loads a Time inside a hash when Time is permitted' do
        time = Time.now
        data = { 'created_at' => time, 'name' => 'test' }
        result = described_class.safe_load(Marshal.dump(data), permitted_classes: %w[Time])
        expect(result['created_at'].to_i).to eq time.to_i
        expect(result['name']).to eq 'test'
      end

      it 'loads a Time inside an array when Time is permitted' do
        time = Time.now
        result = described_class.safe_load(Marshal.dump([time, 'hello']), permitted_classes: %w[Time])
        expect(result[0].to_i).to eq time.to_i
        expect(result[1]).to eq 'hello'
      end

      it 'loads a repeated Time encoded as an object link' do
        time = Time.now

        expect(described_class.safe_load(Marshal.dump([time, time]), permitted_classes: %w[Time])).to eq [time, time]
      end

      it 'rejects a Time instance when no classes are permitted' do
        time = Time.now
        expect do
          described_class.safe_load(Marshal.dump(time))
        end.to raise_error(validation_error, %r{Unsafe Marshal _dump/_load class 'Time'})
      end

      it 'rejects a Time inside a hash when no classes are permitted' do
        data = { 'created_at' => Time.now }
        expect do
          described_class.safe_load(Marshal.dump(data))
        end.to raise_error(validation_error, %r{Unsafe Marshal _dump/_load class 'Time'})
      end
    end

    context 'with safe compound types' do
      it 'loads an empty array' do
        expect(described_class.safe_load(Marshal.dump([]))).to eq []
      end

      it 'loads an array of strings' do
        expect(described_class.safe_load(Marshal.dump(['hello', 'world']))).to eq ['hello', 'world']
      end

      it 'loads an empty hash' do
        expect(described_class.safe_load(Marshal.dump({}))).to eq({})
      end

      it 'loads a hash with string keys and values' do
        data = { 'hello' => 'world', 'foo' => 'bar' }
        expect(described_class.safe_load(Marshal.dump(data))).to eq data
      end

      it 'loads a hash with symbol keys' do
        data = { hello: 'world', foo: 'bar' }
        expect(described_class.safe_load(Marshal.dump(data))).to eq data
      end

      it 'loads nested hashes and arrays' do
        data = {
          'hosts' => [
            { 'address' => '192.0.2.1', 'ports' => [22, 80, 443] },
            { 'address' => '192.0.2.2', 'ports' => [] }
          ],
          'count' => 2,
          'active' => true
        }
        expect(described_class.safe_load(Marshal.dump(data))).to eq data
      end

      it 'loads deeply nested structures' do
        data = { 'a' => { 'b' => { 'c' => { 'd' => [1, [2, [3]]] } } } }
        expect(described_class.safe_load(Marshal.dump(data))).to eq data
      end

      it 'loads mixed-type arrays' do
        data = [1, 'two', :three, 4.0, true, false, nil]
        expect(described_class.safe_load(Marshal.dump(data))).to eq data
      end

      it 'loads repeated symbols encoded as symbol links' do
        data = %i[repeated repeated]

        expect(described_class.safe_load(Marshal.dump(data))).to eq data
      end

      it 'loads repeated strings encoded as object links' do
        string = 'repeated'
        data = [string, string]

        expect(described_class.safe_load(Marshal.dump(data))).to eq data
      end

      it 'loads a self-referential array' do
        data = []
        data << data

        result = described_class.safe_load(Marshal.dump(data))
        expect(result.first).to equal(result)
      end
    end

    context 'with unsafe types' do
      it 'rejects unsafe actual contents hidden by a String subclass' do
        benign_data = Marshal.dump(nil)
        deceptive_string_class = Class.new(String) do
          define_method(:bytes) { benign_data.bytes }
        end
        data = deceptive_string_class.new(Marshal.dump(Object.new))

        expect { described_class.safe_load(data) }.to raise_error(validation_error, /Unsafe Marshal type byte/)
      end

      it 'rejects an arbitrary object instance' do
        data = Marshal.dump(Object.new)
        expect { described_class.safe_load(data) }.to raise_error(validation_error, /Unsafe Marshal type byte/)
      end

      it 'rejects a Struct instance' do
        TestStruct = Struct.new(:x) unless defined?(TestStruct)
        data = Marshal.dump(TestStruct.new(1))
        expect { described_class.safe_load(data) }.to raise_error(validation_error, /Unsafe Marshal type byte/)
      end

      it 'rejects an object nested inside an array' do
        data = Marshal.dump([Object.new])
        expect { described_class.safe_load(data) }.to raise_error(validation_error, /Unsafe Marshal type byte/)
      end

      it 'rejects an object nested inside a hash value' do
        data = Marshal.dump({ 'key' => Object.new })
        expect { described_class.safe_load(data) }.to raise_error(validation_error, /Unsafe Marshal type byte/)
      end

      it 'rejects an object nested inside a hash key' do
        data = Marshal.dump({ Object.new => 'value' })
        expect { described_class.safe_load(data) }.to raise_error(validation_error, /Unsafe Marshal type byte/)
      end

      it 'rejects a class reference' do
        data = Marshal.dump(String)
        expect { described_class.safe_load(data) }.to raise_error(validation_error, /Unsafe Marshal type byte/)
      end

      it 'rejects a module reference' do
        data = Marshal.dump(Kernel)
        expect { described_class.safe_load(data) }.to raise_error(validation_error, /Unsafe Marshal type byte/)
      end
    end

    context 'with malformed data' do
      it 'rejects an empty string' do
        expect { described_class.safe_load('') }.to raise_error(validation_error)
      end

      it 'rejects a truncated stream' do
        data = Marshal.dump('hello')
        expect { described_class.safe_load(data[0..3]) }.to raise_error(validation_error)
      end

      it 'rejects an unsupported Marshal version' do
        data = Marshal.dump('hello')
        bad = "\x05\x09" + data[2..]
        expect { described_class.safe_load(bad) }.to raise_error(validation_error, /Unsupported Marshal version/)
      end
    end
  end

  describe '#validate!' do
    it 'returns true for safe data' do
      data = Marshal.dump({ 'key' => [1, 2, 3] })
      expect(described_class.new(data).validate!).to eq true
    end

    it 'raises for unsafe data' do
      data = Marshal.dump(Object.new)
      expect { described_class.new(data).validate! }.to raise_error(validation_error)
    end

    it 'rejects unsafe actual contents hidden by a String subclass' do
      benign_data = Marshal.dump(nil)
      deceptive_string_class = Class.new(String) do
        define_method(:bytes) { benign_data.bytes }
      end
      data = deceptive_string_class.new(Marshal.dump(Object.new))

      expect { described_class.new(data).validate! }.to raise_error(validation_error, /Unsafe Marshal type byte/)
    end

    it 'accepts input at the maximum validation depth' do
      data = "\x04\x08".b + ("[\x06".b * described_class::MAX_NESTING_DEPTH) + "\x30".b

      expect(described_class.new(data).validate!).to be(true)
    end

    it 'rejects input beyond the maximum validation depth' do
      data = "\x04\x08".b + ("[\x06".b * (described_class::MAX_NESTING_DEPTH + 1)) + "\x30".b

      expect { described_class.new(data).validate! }.to raise_error(validation_error, /nesting exceeds maximum depth/)
    end

    it 'rejects a symbol link that does not reference an earlier symbol' do
      data = "\x04\x08;\x00".b

      expect { described_class.new(data).validate! }.to raise_error(validation_error, /Invalid symbol back-reference/)
    end

    it 'rejects a negative object-link index' do
      data = "\x04\x08@\xFA".b

      expect { described_class.new(data).validate! }.to raise_error(validation_error, /Negative length/)
    end

    it 'rejects an object link that does not reference an earlier object' do
      data = "\x04\x08@\x00".b

      expect { described_class.new(data).validate! }.to raise_error(validation_error, /Invalid object back-reference/)
    end

    it 'rejects an invalid Bignum sign' do
      data = "\x04\x08l!\x00".b

      expect { described_class.new(data).validate! }.to raise_error(validation_error, /Invalid Bignum sign/)
    end
  end

  describe 'symbol-table desync' do
    def marshal_small_int(number)
      number.zero? ? "\x00".b : (number + 5).chr.b
    end

    def marshal_inline_symbol(name)
      ':'.b + marshal_small_int(name.bytesize) + name.b
    end

    def marshal_symbol_link(index)
      ';'.b + marshal_small_int(index)
    end

    let(:time_body_bytes) { "\r\x20\x80\x11\xC0\x00\x00\x00\x00".b }

    # Build a stream that the validator considers safe (only "Time" referenced)
    # but that Marshal.load will use to call `gadget_class_name._load(...)`.
    def build_desync_stream(gadget_class_name)
      "\x04\x08".b +                                               # Marshal 4.8 header
        '['.b + marshal_small_int(3) +                             # Array of 3 elements
        marshal_inline_symbol(gadget_class_name) +                 # elem 0: poisons symbol table[0]
        'u'.b + marshal_inline_symbol('Time') + time_body_bytes +  # elem 1: plants "Time" in @symbol_cache[0]
        'u'.b + marshal_symbol_link(0) + time_body_bytes           # elem 2: ;0 → "Time" in validator, gadget in Ruby
    end

    # Minimal gadget class — _load just records that it was called.
    let(:gadget_class_name) { 'MarshalDesyncGadget' }

    before do
      stub_const(gadget_class_name, Class.new do
        @fired = false
        class << self
          attr_reader :fired

          def _load(_state)
            @fired = true
            new
          end
        end
      end)
    end

    let(:desync_stream) { build_desync_stream(gadget_class_name) }

    it 'rejects a diverged symbol link without invoking the linked class' do
      gadget_klass = Object.const_get(gadget_class_name)

      expect do
        described_class.safe_load(desync_stream, permitted_classes: %w[Time])
      end.to raise_error(validation_error, /Unsafe|not permitted/i)
      expect(gadget_klass.fired).to be(false)
    end
  end

  describe 'negative lengths and counts' do
    negative_length_streams = {
      'Bignum length' => "l+\xFA".b,
      'Float length' => "f\xFA".b,
      'Symbol length' => ":\xFA".b,
      'String length' => "\"\xFA".b,
      'instance-variable count' => "I0\xFA".b,
      'Array count' => "[\xFA".b,
      'Hash count' => "{\xFA".b,
      'Hash-with-default count' => "}\xFA".b,
      'inline class-name length' => "u:\xFA".b,
      '_dump payload length' => "u:\x09Time\xFA".b
    }.freeze

    negative_length_streams.each do |field, body|
      it "rejects a negative #{field}" do
        data = "\x04\x08".b + body

        expect do
          described_class.new(data, permitted_classes: %w[Time]).validate!
        end.to raise_error(validation_error, /Negative length/)
      end
    end
  end
end

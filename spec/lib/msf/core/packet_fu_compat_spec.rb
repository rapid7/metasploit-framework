# -*- coding:binary -*-

require 'spec_helper'
require 'packetfu'

RSpec.describe Msf::PacketFuCompat do
  # Minimal StructFu-based holder that mimics how packetfu headers use
  # StructFu#typecast from within attribute setters.
  let(:holder_class) do
    Class.new(::Struct.new(:value)) do
      include ::StructFu

      def value=(input)
        typecast(input)
      end
    end
  end

  def holder_with_frame(frames)
    holder = holder_class.new
    holder[:value] = ::StructFu::Int8.new
    holder.define_singleton_method(:caller) { |*_args| Array(frames) }
    holder
  end

  describe '.apply!' do
    it 'does not stack duplicate patches when applied repeatedly' do
      described_class.apply!
      ancestors_before = ::StructFu.ancestors.dup

      described_class.apply!

      expect(::StructFu.ancestors).to eq(ancestors_before)
      expect(::StructFu.instance_variable_get(:@msf_typecast_compat)).to eq(true)
    end

    context 'when patched' do
      before(:all) { described_class.apply! }

      it 'does not break normal packet construction' do
        expect { ::PacketFu::ARPPacket.new }.not_to raise_error
      end

      it 'parses pre-Ruby-3.4 backtrace frames' do
        holder = holder_with_frame('lib/packetfu/protos/eth/header.rb:168:in `value=\'')
        holder.value = 42
        expect(holder[:value].to_i).to eq(42)
      end

      it 'parses Ruby 3.4+ backtrace frames with qualified method names' do
        holder = holder_with_frame("vendor/bundle/ruby/3.4.0/gems/packetfu-2.0.0/lib/packetfu/structfu.rb:20:in 'StructFu#value='")
        holder.value = 42
        expect(holder[:value].to_i).to eq(42)
      end

      it 'parses Ruby 3.4+ singleton method backtrace frames' do
        holder = holder_with_frame("lib/packetfu/protos/tcp/option.rb:143:in 'PacketFu::TCPOption::NOP#value='")
        holder.value = 7
        expect(holder[:value].to_i).to eq(7)
      end

      it 'skips unrelated frames when locating the setter frame' do
        holder = holder_with_frame([
          "lib/some/wrapper.rb:10:in 'Something#wrap'",
          'lib/packetfu/protos/eth/header.rb:168:in `value=\''
        ])
        holder.value = 5
        expect(holder[:value].to_i).to eq(5)
      end

      it 'raises an informative error when the frame cannot be parsed' do
        holder = holder_with_frame('totally unexpected frame')
        expect { holder.value = 1 }.to raise_error(NameError, /could not determine the attribute being set/)
      end
    end
  end
end

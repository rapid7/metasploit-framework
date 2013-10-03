require 'spec_helper'

describe Metasploit::Framework::Spec::Constants do
  context 'each' do
    def each(&block)
      described_class.each(&block)
    end

    let(:expected_child_name) do
      :Child
    end

    let(:constant_value) do
      double('Constant Value')
    end

    context 'with Msf::Modules' do
      before(:each) do
        stub_const("Msf::Modules::#{expected_child_name}", constant_value)
      end

      it 'should return constants under Msf::Modules' do
        expect { |block|
          each(&block)
        }.to yield_with_args(Msf::Modules, expected_child_name)
      end
    end

    context 'with Msf::Payloads' do
      before(:each) do
        stub_const("Msf::Payloads::#{expected_child_name}", constant_value)
      end

      it 'should return constants under Msf::Payloads' do
        expect { |block|
          each(&block)
        }.to yield_with_args(Msf::Payloads, expected_child_name)
      end
    end

    context 'without Msf::Modules or Msf::Payloads constants' do
      specify {
        expect { |block|
          each(&block)
        }.not_to yield_control
      }
    end
  end
end
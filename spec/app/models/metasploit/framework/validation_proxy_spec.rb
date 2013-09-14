require 'spec_helper'

describe Metasploit::Framework::ValidationProxy do
  subject(:validation_proxy) do
    described_class.new(target: target)
  end

  let(:target) do
    Module.new do
      def self.target_method(*args, &block)
        'target_method'
      end
    end
  end

  context '#method_missing' do
    context 'with method to which target responds' do
      let(:method_name) do
        :target_method
      end

      it 'should call method on target' do
        target.should_receive(:target_method)

        validation_proxy.target_method
      end

      it 'should pass args to target method' do
        args = [:a, :b]
        target.should_receive(:target_method).with(*args)

        validation_proxy.target_method(*args)
      end

      it 'should pass block to target method' do
        block = lambda {}

        target.should_receive(:target_method).with(&block)

        validation_proxy.target_method(&block)
      end
    end

    context 'without method to which target responds' do
      it 'should call super' do
        expect {
          validation_proxy.non_target_method
        }.to raise_error(NoMethodError)
      end
    end
  end
end
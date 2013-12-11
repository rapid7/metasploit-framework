require 'spec_helper'

describe Metasploit::Framework::Module::Instance::Logging do
  include_context 'database cleaner'

  subject(:base_instance) do
    base_class.new
  end

  #
  # lets
  #

  let(:base_class) do
    described_class = self.described_class

    Class.new do
      include described_class
    end
  end

  let(:module_instance) do
    FactoryGirl.build(:mdm_module_instance)
  end

  it { should be_a Metasploit::Framework::Module::Class::Logging }

  context '#log_module_instance_error' do
    subject(:log_module_instance_error) do
      base_instance.log_module_instance_error(module_instance, error)
    end

    let(:error) do
      error = nil

      begin
        raise
      rescue Exception => error
      end

      error
    end

    it 'should use #module_instance_location' do
      base_instance.should_receive(:module_instance_location)

      log_module_instance_error
    end

    it 'should log error' do
      base_instance.should_receive(:elog)

      log_module_instance_error
    end

    context 'log message' do
      it 'should include error class' do
        error.should_receive(:class)

        log_module_instance_error
      end

      it 'should include error itself' do
        error.should_receive(:to_s)

        log_module_instance_error
      end

      it 'should include backtrace' do
        error.should_receive(:backtrace).and_return([])

        log_module_instance_error
      end
    end
  end

  context '#module_instance_location' do
    subject(:module_instance_location) do
      base_instance.module_instance_location(module_instance)
    end

    it 'should be module_class_location of module_instance.module_class' do
      module_instance_location.should == base_instance.module_class_location(module_instance.module_class)
    end
  end

  context '#rescue_module_instance_error' do
    def rescue_module_instance_error(&block)
      base_instance.rescue_module_instance_error(module_instance, error_class, &block)
    end

    let(:error_class) do
      Exception
    end

    context 'with error' do
      it 'should log error' do
        base_instance.should_receive(:log_module_instance_error).with(
            module_instance,
            an_instance_of(error_class)
        )

        rescue_module_instance_error {
          raise error_class, "message"
        }
      end
    end

    context 'without error' do
      it 'should return yieldreturn' do
        yieldreturn = double('Yield Return')

        rescue_module_instance_error {
          yieldreturn
        }.should == yieldreturn
      end
    end
  end
end
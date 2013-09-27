require 'spec_helper'

describe Metasploit::Framework::Thread do
  subject(:thread) do
    FactoryGirl.create(:metasploit_framework_thread)
  end

  let(:error) do
    Exception.new(message)
  end

  let(:message) do
    'Error Message'
  end

  context 'factories' do
    context 'metasploit_framework_thread' do
      subject(:metasploit_framework_thread) do
        FactoryGirl.build(:metasploit_framework_thread)
      end

      it { should be_valid }

      its(:critical) { should be_false }
    end
  end

  context 'validations' do
    it { should validate_presence_of :backtrace }
    it { should validate_presence_of :block }
    it { should ensure_inclusion_of(:critical).in_array([false, true]) }
    it { should validate_presence_of :name }
  end

  context '#format_error_log_message' do
    subject(:format_error_log_message) do
      thread.send(:format_error_log_message, error)
    end

    let(:error_subsection) do
      "Error:\n"
    end

    it 'should include #backtrace' do
      thread.backtrace.each do |line|
        format_error_log_message.should include(line)
      end
    end

    it 'should include #critical' do
      format_error_log_message.should include(thread.critical.to_s)
    end

    it 'should include #name' do
      format_error_log_message.should include(thread.name)
    end

    context 'with error' do
      let(:backtrace_subsection) do
        '    Backtrace:'
      end

      it 'should include error subsection' do
        format_error_log_message.should include(error_subsection)
      end

      it 'should include error.class' do
        format_error_log_message.should include(error.class.to_s)
      end

      it 'should include error as string' do
        format_error_log_message.should include(error.to_s)
      end

      context 'with backtrace' do
        before(:each) do
          error.set_backtrace(caller)
        end

        it 'should include backtrace subsection' do
          format_error_log_message.should include(backtrace_subsection)
        end

        it 'should include backtrace' do
          error.backtrace.each do |line|
            format_error_log_message.should include(line)
          end
        end
      end

      context 'without backtrace' do
        it 'should not include backtrace subsection' do
          format_error_log_message.should_not include(backtrace_subsection)
        end
      end
    end

    context 'without error' do
      let(:error) do
        nil
      end

      it 'should not include error subsection' do
        format_error_log_message.should_not include(error_subsection)
      end
    end
  end

  context '#initialize' do
    context 'with &block' do
      let(:block_block) do
        ->(*args) { args }
      end

      context 'with :block' do
        subject(:thread) do
          described_class.new(block: option_block, &block_block)
        end

        let(:option_block) do
          ->(*args) { args }
        end

        it 'should raise ArgumentError' do
          expect {
            thread
          }.to raise_error(ArgumentError)
        end

        it 'should not log error' do
          described_class.any_instance.should_not_receive(:elog)

          expect {
            thread
          }.to raise_error
        end
      end

      context 'without :block' do
        subject(:thread) {
          described_class.new(&block_block)
        }

        it 'should set #block to &block' do
          thread.block.should == block_block
        end
      end
    end
  end

  context '#log_and_raise' do
    subject(:log_and_raise) do
      thread.log_and_raise(error)
    end

    let(:error) do
      Exception.new("Metasploit::Framework::Thread#raise error")
    end

    it 'should use #format_error_log_message to produce argument to elog' do
      formatted = double('Formatted')
      thread.should_receive(:format_error_log_message).with(error).and_return(formatted)
      thread.should_receive(:elog).with(formatted)

      expect {
        log_and_raise
      }.to raise_error
    end

    it 'should log error' do
      thread.should_receive(:elog)

      expect {
        log_and_raise
      }.to raise_error
    end

    it 'should raise error' do
      expect {
        log_and_raise
      }.to raise_error(error)
    end
  end

  context '#run' do
    subject(:run) do
      thread.run
    end

    let(:block) do
      ->(*args) { args }
    end

    let(:block_arguments) do
      [
          :a,
          :b
      ]
    end

    let(:thread) do
      FactoryGirl.create(
          :metasploit_framework_thread,
          block: block,
          block_arguments: block_arguments
      )
    end

    it 'should pass *block_arguments to block' do
      run.should == block_arguments
    end
  end
end
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

  context '#as_json' do
    subject(:as_json) do
      thread.as_json
    end

    context '[:backtrace]' do
      subject(:json_backtrace) do
        as_json[:backtrace]
      end

      it 'should be #backtrace' do
        json_backtrace.should == thread.backtrace
      end

      it 'should utf-8 encode each line in #backtrace' do
        thread.backtrace.each do |line|
          line.should_receive(:encode).with('utf-8')
        end

        as_json
      end
    end

    context '[:critical]' do
      subject(:json_critical) do
        as_json[:critical]
      end

      it 'should be #critical' do
        json_critical.should == thread.critical
      end
    end

    context '[:name]' do
      subject(:json_name) do
        as_json[:name]
      end

      it 'should be #name' do
        json_name.should == thread.name
      end

      it 'should encode #name in utf-8' do
        thread.name.should_receive(:encode).with('utf-8')

        as_json
      end
    end
  end

  context '#error_as_json' do
    subject(:error_as_json) do
      thread.send(:error_as_json, error)
    end

    context '[:backtrace]' do
      subject(:json_backtrace) do
        error_as_json[:backtrace]
      end

      context 'with Exception#backtrace' do
        let(:backtrace) do
          caller
        end

        before(:each) do
          error.set_backtrace(backtrace)
        end

        it 'should be error.backtrace' do
          json_backtrace.should == backtrace
        end
      end

      context 'without Exception#backtrace' do
        it { should be_nil }
      end
    end

    context '[:class]' do
      subject(:json_class) do
        error_as_json[:class]
      end

      it 'should be error.class.name' do
        json_class.should == error.class.name
      end
    end

    context '[:message]' do
      subject(:json_message) do
        error_as_json[:message]
      end

      it 'should be error message' do
        json_message.should == error.to_s
      end

      it 'should convert the error message to utf-8' do
        error_message = double('Error message')
        error_message.should_receive(:encode).with('utf-8')
        error.stub(to_s: error_message)

        json_message
      end
    end
  end

  context '#format_error_log_message' do
    subject(:format_error_log_message) do
      thread.send(:format_error_log_message, error)
    end

    it 'should use thread as JSON' do
      thread.should_receive(:as_json).and_return({})

      format_error_log_message
    end

    it 'should use error as JSON' do
      thread.should_receive(:error_as_json).with(error).and_return({})

      format_error_log_message
    end

    it 'should use thread as root key' do
      format_error_log_message.should start_with("---\n:thread:\n")
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
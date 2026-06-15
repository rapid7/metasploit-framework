# frozen_string_literal: true

require 'spec_helper'
require 'rex/ui/subscriber'
require 'rex/ui/text/input/buffer'

RSpec.describe Rex::Ui::Subscriber do
  let(:subscriber_class) do
    Class.new do
      include Rex::Ui::Subscriber
    end
  end

  let(:subscriber) { subscriber_class.new }

  context 'closing handles on replacement' do
    describe '#reset_ui' do
      context 'when user_input responds to close' do
        it 'calls close on the existing user_input before nilling' do
          old_input = double('closeable_input')
          allow(old_input).to receive(:close)

          subscriber.init_ui(old_input, nil)
          subscriber.reset_ui

          expect(old_input).to have_received(:close)
        end
      end
    end

    describe '#init_ui' do
      context 'when replacing user_input with a different closeable handle' do
        it 'calls close on the old user_input before assigning the new one' do
          old_input = double('old_closeable_input')
          allow(old_input).to receive(:close)
          new_input = double('new_input')

          subscriber.init_ui(old_input, nil)
          subscriber.init_ui(new_input, nil)

          expect(old_input).to have_received(:close)
        end
      end
    end

    describe 'FD stability with real Input::Buffer instances' do
      it 'does not grow FD count when calling init_ui repeatedly' do
        initial_fd_count = Dir.glob('/dev/fd/*').count

        5.times do
          buffer = Rex::Ui::Text::Input::Buffer.new
          subscriber.init_ui(buffer, nil)
        end
        subscriber.reset_ui

        final_fd_count = Dir.glob('/dev/fd/*').count

        # If handles are properly closed, FD count should not grow.
        # On unfixed code, each Input::Buffer leaks a socket pair (2 FDs each).
        expect(final_fd_count).to be <= initial_fd_count + 2
      end
    end
  end

  context 'Graceful close failure handling' do
    describe '#reset_ui' do
      it 'does not raise when user_input.close raises IOError' do
        handle = double('already_closed')
        allow(handle).to receive(:close).and_raise(IOError, 'closed stream')

        subscriber.user_input = handle
        expect { subscriber.reset_ui }.not_to raise_error
      end

      it 'does not raise when user_input.close raises Errno::EBADF' do
        handle = double('bad_fd')
        allow(handle).to receive(:close).and_raise(Errno::EBADF)

        subscriber.user_input = handle
        expect { subscriber.reset_ui }.not_to raise_error
      end

      it 'nils user_input even when close raises' do
        handle = double('error_handle')
        allow(handle).to receive(:close).and_raise(IOError)

        subscriber.user_input = handle
        subscriber.reset_ui

        expect(subscriber.user_input).to be_nil
      end

      it 'nils user_output' do
        output = double('output')
        subscriber.user_output = output
        subscriber.reset_ui

        expect(subscriber.user_output).to be_nil
      end
    end

    describe '#init_ui' do
      it 'does not raise when old user_input.close raises IOError' do
        old_input = double('already_closed')
        allow(old_input).to receive(:close).and_raise(IOError, 'closed stream')
        new_input = double('new_input')

        subscriber.init_ui(old_input, nil)
        expect { subscriber.init_ui(new_input, nil) }.not_to raise_error
        expect(subscriber.user_input).to eq(new_input)
      end

      it 'does not raise when old user_input.close raises Errno::EBADF' do
        old_input = double('bad_fd')
        allow(old_input).to receive(:close).and_raise(Errno::EBADF)
        new_input = double('new_input')

        subscriber.init_ui(old_input, nil)
        expect { subscriber.init_ui(new_input, nil) }.not_to raise_error
        expect(subscriber.user_input).to eq(new_input)
      end
    end
  end

  context 'non-closeable and same-handle cases' do
    describe '#reset_ui' do
      context 'when user_input is nil' do
        it 'does not raise' do
          subscriber.user_input = nil
          expect { subscriber.reset_ui }.not_to raise_error
        end
      end

      context 'when user_input does not respond to close' do
        it 'does not raise' do
          non_closeable = Object.new
          subscriber.user_input = non_closeable
          expect { subscriber.reset_ui }.not_to raise_error
        end
      end
    end

    describe '#init_ui' do
      context 'on a fresh subscriber with no existing handles' do
        it 'assigns input and output handles correctly' do
          input = double('input')
          output = double('output')

          subscriber.init_ui(input, output)

          expect(subscriber.user_input).to eq(input)
          expect(subscriber.user_output).to eq(output)
        end
      end

      context 'when called with the same handle already assigned' do
        it 'does not close the active handle' do
          handle = double('closeable_handle', close: nil)
          subscriber.user_input = handle

          subscriber.init_ui(handle, nil)

          expect(handle).not_to have_received(:close)
          expect(subscriber.user_input).to eq(handle)
        end
      end

      context 'when replacing a non-closeable handle with a new one' do
        it 'does not raise' do
          non_closeable = Object.new
          subscriber.user_input = non_closeable

          new_input = double('new_input')
          expect { subscriber.init_ui(new_input, nil) }.not_to raise_error
          expect(subscriber.user_input).to eq(new_input)
        end
      end
    end
  end

  describe '#copy_ui' do
    it 'copies input and output from another subscriber' do
      source = subscriber_class.new
      input = double('input')
      output = double('output')
      source.init_ui(input, output)

      subscriber.copy_ui(source)

      expect(subscriber.user_input).to eq(input)
      expect(subscriber.user_output).to eq(output)
    end

    it 'closes existing closeable user_input when copying' do
      old_input = double('old_input')
      allow(old_input).to receive(:close)
      subscriber.init_ui(old_input, nil)

      source = subscriber_class.new
      new_input = double('new_input')
      source.init_ui(new_input, nil)

      subscriber.copy_ui(source)

      expect(old_input).to have_received(:close)
    end
  end

  describe '#gets' do
    it 'delegates to user_input.gets' do
      input = double('input', gets: "hello\n")
      subscriber.user_input = input

      expect(subscriber.gets).to eq("hello\n")
    end

    it 'returns nil when user_input is nil' do
      subscriber.user_input = nil
      expect(subscriber.gets).to be_nil
    end
  end

  describe Rex::Ui::Subscriber::Output do
    let(:output) { double('output') }

    before do
      allow(output).to receive(:prompting?).and_return(false)
      subscriber.user_output = output
    end

    describe '#print_line' do
      it 'delegates to user_output.print_line' do
        allow(output).to receive(:print_line)
        subscriber.print_line('test message')
        expect(output).to have_received(:print_line).with('test message')
      end

      it 'does nothing when user_output is nil' do
        subscriber.user_output = nil
        expect { subscriber.print_line('test') }.not_to raise_error
      end
    end

    describe '#print_status' do
      it 'delegates to user_output.print_status' do
        allow(output).to receive(:print_status)
        subscriber.print_status('status message')
        expect(output).to have_received(:print_status).with('status message')
      end

      it 'does nothing when user_output is nil' do
        subscriber.user_output = nil
        expect { subscriber.print_status('test') }.not_to raise_error
      end
    end

    describe '#print_error' do
      it 'delegates to user_output.print_error' do
        allow(output).to receive(:print_error)
        subscriber.print_error('error message')
        expect(output).to have_received(:print_error).with('error message')
      end

      it 'does nothing when user_output is nil' do
        subscriber.user_output = nil
        expect { subscriber.print_error('test') }.not_to raise_error
      end
    end

    describe '#print_good' do
      it 'delegates to user_output.print_good' do
        allow(output).to receive(:print_good)
        subscriber.print_good('good message')
        expect(output).to have_received(:print_good).with('good message')
      end

      it 'does nothing when user_output is nil' do
        subscriber.user_output = nil
        expect { subscriber.print_good('test') }.not_to raise_error
      end
    end

    describe '#print_warning' do
      it 'delegates to user_output.print_warning' do
        allow(output).to receive(:print_warning)
        subscriber.print_warning('warning message')
        expect(output).to have_received(:print_warning).with('warning message')
      end

      it 'does nothing when user_output is nil' do
        subscriber.user_output = nil
        expect { subscriber.print_warning('test') }.not_to raise_error
      end
    end

    describe '#print' do
      it 'delegates to user_output.print' do
        allow(output).to receive(:print)
        subscriber.print('raw text')
        expect(output).to have_received(:print).with('raw text')
      end

      it 'does nothing when user_output is nil' do
        subscriber.user_output = nil
        expect { subscriber.print('test') }.not_to raise_error
      end
    end

    describe '#flush' do
      it 'delegates to user_output.flush' do
        allow(output).to receive(:flush)
        subscriber.flush
        expect(output).to have_received(:flush)
      end

      it 'does nothing when user_output is nil' do
        subscriber.user_output = nil
        expect { subscriber.flush }.not_to raise_error
      end
    end

    context 'when output is prompting' do
      before do
        allow(output).to receive(:prompting?).and_return(true)
        allow(output).to receive(:prompting)
        allow(output).to receive(:print_line)
      end

      it 'prints a blank line before print_line' do
        subscriber.print_line('msg')
        expect(output).to have_received(:prompting).with(false)
        expect(output).to have_received(:print_line).with(no_args)
        expect(output).to have_received(:print_line).with('msg')
      end
    end
  end
end

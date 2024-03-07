# -*- coding:binary -*-
require 'spec_helper'
require 'rex/ui/text/shell/history_manager'
require 'readline'
require 'reline'
require 'tempfile'

RSpec.describe Rex::Ui::Text::Shell::HistoryManager do
  subject { described_class.send(:new) }
  let(:readline_available) { false }
  let(:reline_available) { false }

  before(:each) do
    allow(subject).to receive(:readline_available?).and_return(readline_available)
    allow(subject).to receive(:reline_available?).and_return(reline_available)
  end

  describe '#with_context' do
    context 'when there is not an existing stack' do
      it 'continues to have an empty stack' do
        subject.with_context {
          # noop
        }
        expected_contexts = [
        ]
        expect(subject._contexts).to eq(expected_contexts)
      end

      it 'yields and starts a new history context' do
        (expect do |block|
          subject.with_context(name: 'a') do
            expected_contexts = [
              { history_file: nil, input_library: :readline, name: 'a' },
            ]
            expect(subject._contexts).to eq(expected_contexts)
            block.to_proc.call
          end
        end).to yield_control.once
      end
    end

    context 'when there is an existing stack' do
      before(:each) do
        subject.send(:push_context, history_file: nil, input_library: :readline, name: 'a')
      end

      it 'continues to have the previous existing stack' do
        subject.with_context {
          # noop
        }
        expected_contexts = [
          { history_file: nil, input_library: :readline, name: 'a' },
        ]
        expect(subject._contexts).to eq(expected_contexts)
      end

      it 'yields and starts a new history context' do
        (expect do |block|
          subject.with_context(name: 'b') do
            expected_contexts = [
              { history_file: nil, input_library: :readline, name: 'a' },
              { history_file: nil, input_library: :readline, name: 'b' },
            ]
            expect(subject._contexts).to eq(expected_contexts)
            block.to_proc.call
          end
        end).to yield_control.once
      end

      it 'continues to have the previous stack when an exception is raised' do
        expect do
          subject.with_context {
            raise ArgumentError, 'Mock error'
          }
        end.to raise_exception ArgumentError, 'Mock error'
        expected_contexts = [
          { history_file: nil, input_library: :readline, name: 'a' },
        ]
        expect(subject._contexts).to eq(expected_contexts)
      end
    end
  end

  describe '#push_context' do
    context 'when the stack is empty' do
      it 'stores the history contexts' do
        subject.send(:push_context, history_file: nil, input_library: :readline, name: 'a')
        expected_contexts = [
          { history_file: nil, input_library: :readline, name: 'a' }
        ]
        expect(subject._contexts).to eq(expected_contexts)
      end
    end

    context 'when multiple values are pushed' do
      it 'stores the history contexts' do
        subject.send(:push_context, history_file: nil, name: 'a')
        subject.send(:push_context, history_file: nil, input_library: :readline, name: 'b')
        subject.send(:push_context, history_file: nil, input_library: :reline, name: 'c')
        expected_contexts = [
          { history_file: nil, input_library: :readline, name: 'a' },
          { history_file: nil, input_library: :readline, name: 'b' },
          { history_file: nil, input_library: :reline, name: 'c' },
        ]
        expect(subject._contexts).to eq(expected_contexts)
      end
    end
  end

  describe '#pop_context' do
    context 'when the stack is empty' do
      it 'continues to have an empty stack' do
        subject.send(:pop_context)
        expected_contexts = [
        ]
        expect(subject._contexts).to eq(expected_contexts)
      end
    end

    context 'when the stack is not empty' do
      it 'continues to have a non-empty stack' do
        subject.send(:push_context, history_file: nil, name: 'a')
        subject.send(:push_context, history_file: nil, name: 'b')
        subject.send(:pop_context)
        expected_contexts = [
          { history_file: nil, input_library: :readline, name: 'a' },
        ]
        expect(subject._contexts).to eq(expected_contexts)
      end
    end
  end

  describe '#store_history_file' do
    context 'when storing above max history lines' do
      def clear_readline
        ::Readline::HISTORY.pop until ::Readline::HISTORY.empty?
      end

      def clear_reline
        ::Reline::HISTORY.pop until ::Reline::HISTORY.empty?
      end

      before(:each) do
        @history_file = ::Tempfile.new('history')

        # Store the current history & clear Readline && Reline
        @readline_history_before = ::Readline::HISTORY.to_a
        @reline_history_before = ::Reline::HISTORY.to_a

        clear_readline
        clear_reline
      end

      after(:each) do
        clear_readline
        @readline_history_before.each { |line| ::Readline::HISTORY << line }

        clear_reline
        @reline_history_before.each { |line| ::Reline::HISTORY << line }
      end

      it 'truncates to max allowed history' do
        allow(subject).to receive(:_remaining_work).and_call_original
        allow(subject).to receive(:store_history_file).and_call_original

        history_choices = %w[sessions run query help]
        max_history = subject.class::MAX_HISTORY
        # Populate example history we want to store
        total_times = max_history + 10
        total_times.times do
          ::Readline::HISTORY << history_choices[rand(history_choices.count)]
        end

        context = { input_library: :readline, history_file: @history_file.path, name: 'history'}

        subject.send(:store_history_file, context)

        sleep(0.1) until subject._remaining_work.empty?

        expect(@history_file.read.split("\n").count).to eq(max_history)
      end
    end
  end

  describe '#load_history_file' do
    def clear_readline
      ::Readline::HISTORY.pop until ::Readline::HISTORY.empty?
    end

    def clear_reline
      ::Reline::HISTORY.pop until ::Reline::HISTORY.empty?
    end

    before(:each) do
      @history_file = ::Tempfile.new('history')

      # Store the current history & clear Readline && Reline
      @readline_history_before = ::Readline::HISTORY.to_a
      @reline_history_before = ::Reline::HISTORY.to_a

      clear_readline
      clear_reline
    end

    after(:each) do
      clear_readline
      @readline_history_before.each { |line| ::Readline::HISTORY << line }

      clear_reline
      @reline_history_before.each { |line| ::Reline::HISTORY << line }
    end

    context 'when history file is not accessible' do
      it 'the library history remains unchanged' do
        history_file = ::File.join('does/not/exist/history')
        context = { input_library: :readline, history_file: history_file, name: 'history' }

        subject.send(:load_history_file, context)
        expect(::Readline::HISTORY.to_a).to eq(@readline_history_before)
      end
    end

    context 'when history file is accessible' do
      it 'correctly loads the history' do
        history_file = ::File.join(Msf::Config.history_file)
        history_lines = ::File.read(history_file).split("\n")

        context = { input_library: :readline, history_file: history_file, name: 'history' }

        subject.send(:load_history_file, context)

        expect(::Readline::HISTORY.to_a).to eq(history_lines)
      end
    end
  end
end

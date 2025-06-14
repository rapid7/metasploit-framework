# -*- coding:binary -*-
require 'spec_helper'
require 'rex/ui/text/shell/history_manager'
require 'tempfile'

RSpec.describe Rex::Ui::Text::Shell::HistoryManager do
  include_context 'wait_for_expect'

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
    let(:initial_history) { [] }
    let(:history_mock) { initial_history }
    let(:history_choices) { %w[sessions run query help] }
    let(:history_file) { ::Tempfile.new('history') }

    after(:each) do
      # https://ruby-doc.org/stdlib-2.5.3/libdoc/tempfile/rdoc/Tempfile.html#class-Tempfile-label-Explicit+close
      history_file.unlink
      subject._close
    end

    [
      { history_size: described_class::MAX_HISTORY + 10, expected_size: described_class::MAX_HISTORY },
      { history_size: described_class::MAX_HISTORY, expected_size: described_class::MAX_HISTORY },
      { history_size: described_class::MAX_HISTORY - 10, expected_size: described_class::MAX_HISTORY - 10 },
    ].each do |test|
      context "when storing #{test[:history_size]} lines" do
        it "correctly stores #{test[:expected_size]} lines" do
          allow(subject).to receive(:store_history_file).and_call_original
          allow(subject).to receive(:map_library_to_history).and_return(history_mock)

          test[:history_size].times do
            # This imitates the user typing in a command and pressing the 'enter' key.
            history_mock << history_choices.sample
          end

          context = { input_library: :readline, history_file: history_file.path, name: 'history'}

          subject.send(:store_history_file, context)

          wait_for_expect do
            expect(history_file.read.split("\n").count).to eq(test[:expected_size])
          end
        end
      end
    end
  end

  describe '#load_history_file' do
    let(:initial_history) { [] }
    let(:history_mock) { initial_history }
    let(:history_choices) { %w[sessions run query help] }
    let(:history_file) { ::Tempfile.new('history') }

    after(:each) do
      history_file.unlink
      subject._close
    end

    context 'when history file is not accessible' do
      it 'the library history remains unchanged' do
        allow(subject).to receive(:map_library_to_history).and_return(history_mock)
        history_file = ::File.join('does', 'not', 'exist', 'history')
        context = { input_library: :readline, history_file: history_file, name: 'history' }

        subject.send(:load_history_file, context)
        expect(history_mock).to eq(initial_history)
      end
    end

    context 'when history file is accessible' do
      it 'correctly loads the history' do
        allow(subject).to receive(:map_library_to_history).and_return(history_mock)

        # Populate our own history file with random entries.
        # Using this allows us to not have to worry about history files present/not present on disk.
        new_history = []
        50.times do
          new_history << history_choices.sample
        end
        history_file.puts new_history
        history_file.rewind

        context = { input_library: :readline, history_file: history_file.path, name: 'history' }

        subject.send(:load_history_file, context)

        expect(history_mock).to eq(new_history)
      end
    end
  end
end

# -*- coding:binary -*-
require 'spec_helper'
require 'rex/ui/text/shell/history_manager'

RSpec.describe Rex::Ui::Text::Shell::HistoryManager do
  subject { described_class.send(:new) }
  let(:readline_available) { false }

  before(:each) do
    allow(subject).to receive(:readline_available?).and_return(readline_available)
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
              { history_file: nil, name: 'a' },
            ]
            expect(subject._contexts).to eq(expected_contexts)
            block.to_proc.call
          end
        end).to yield_control.once
      end
    end

    context 'when there is an existing stack' do
      before(:each) do
        subject.send(:push_context, history_file: nil, name: 'a')
      end

      it 'continues to have the previous existing stack' do
        subject.with_context {
          # noop
        }
        expected_contexts = [
          { history_file: nil, name: 'a' },
        ]
        expect(subject._contexts).to eq(expected_contexts)
      end

      it 'yields and starts a new history context' do
        (expect do |block|
          subject.with_context(name: 'b') do
            expected_contexts = [
              { history_file: nil, name: 'a' },
              { history_file: nil, name: 'b' },
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
          { history_file: nil, name: 'a' },
        ]
        expect(subject._contexts).to eq(expected_contexts)
      end
    end
  end

  describe '#push_context' do
    context 'when the stack is empty' do
      it 'stores the history contexts' do
        subject.send(:push_context, history_file: nil, name: 'a')
        expected_contexts = [
          { history_file: nil, name: 'a' }
        ]
        expect(subject._contexts).to eq(expected_contexts)
      end
    end

    context 'when multiple values are pushed' do
      it 'stores the history contexts' do
        subject.send(:push_context, history_file: nil, name: 'a')
        subject.send(:push_context, history_file: nil, name: 'b')
        subject.send(:push_context, history_file: nil, name: 'c')
        expected_contexts = [
          { history_file: nil, name: 'a' },
          { history_file: nil, name: 'b' },
          { history_file: nil, name: 'c' },
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
      it 'continues to have an empty stack' do
        subject.send(:push_context, history_file: nil, name: 'a')
        subject.send(:push_context, history_file: nil, name: 'b')
        subject.send(:pop_context)
        expected_contexts = [
          { history_file: nil, name: 'a' },
        ]
        expect(subject._contexts).to eq(expected_contexts)
      end
    end
  end
end

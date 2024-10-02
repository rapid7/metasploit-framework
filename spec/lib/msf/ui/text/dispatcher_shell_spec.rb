require 'spec_helper'
require 'readline'

RSpec.describe Rex::Ui::Text::DispatcherShell do
  let(:prompt) { '%undmsf6%clr' }
  let(:prompt_char) { '%clr>' }
  let(:subject) do
    dummy_class = Class.new
    dummy_class.include described_class
    dummy_class.new(prompt, prompt_char)
  end

  def mock_dispatcher_for(completions:)
    dispatcher = double :mock_dispatcher
    allow(dispatcher).to receive(:tab_complete_helper) do |_current_word, _preceding_words|
      completions
    end
    dispatcher
  end

  describe '#tab_complete' do
    let(:dispatcher_stack) do
      [
        mock_dispatcher_for(completions: completions)
      ]
    end

    before(:each) do
      allow(subject).to receive(:dispatcher_stack).and_return(dispatcher_stack)
    end

    context 'when tab completing options' do
      let(:completions) { ['username=', 'password='] }
      [
        { input: '', expected: nil },
        { input: '      ', expected: ['      username=', '      password='] },
        { input: '      u', expected: ['      username='] },
        { input: 'password=abc user', expected: ['password=abc username='] },
        { input: 'password=a\\ b\\ c user', expected: ['password=a\\ b\\ c username='] },
        { input: "'password=a b c' user", expected: ["'password=a b c' username="] },
        { input: "password='a b c' user", expected: ["password='a b c' username="] },
        { input: "password='a b c'       user", expected: ["password='a b c'       username="] },
        { input: 'username=', expected: ['username='] },
        { input: 'password=abc ', expected: ['password=abc username=', 'password=abc password='] }
      ].each do |test|
        it "provides completion for #{test[:input].inspect}" do
          expect(subject.tab_complete(test[:input])).to eql(test[:expected])
        end
      end
    end

    context 'when tab completing paths' do
      context 'when the paths are relative' do
        let(:completions) { ['$Recycle.Bin', 'Program Files (x86)', 'Program Files', 'Documents and Settings'] }

        [
          { input: '', expected: nil },
          { input: 'cd  ', expected: ['cd  $Recycle.Bin', 'cd  Program\\ Files\\ (x86)', 'cd  Program\\ Files', 'cd  Documents\\ and\\ Settings'] },
          { input: 'cd  P', expected: ['cd  Program\\ Files\\ (x86)', 'cd  Program\\ Files'] },
          { input: "cd  'Progra", expected: ["cd  'Program Files (x86)'", "cd  'Program Files'"] },
          { input: 'cd  "Program"', expected: ['cd  "Program Files (x86)"', 'cd  "Program Files"'] },
          { input: "cd  'Program Files", expected: ["cd  'Program Files (x86)'", "cd  'Program Files'"] },
          { input: "cd  'Program\\ Files", expected: [] },
          { input: "cd  'Program\\\\ Files", expected: [] },
          { input: 'cd  Program\\ Files', expected: ['cd  Program\\ Files\\ (x86)', 'cd  Program\\ Files'] },
        ].each do |test|
          it "provides completion for #{test[:input].inspect}" do
            expect(subject.tab_complete(test[:input])).to eql(test[:expected])
          end
        end
      end

      context 'when the paths are absolute' do
        let(:completions) { ['C:\\$Recycle.Bin', 'C:\\Program Files (x86)', 'C:\\Program Files', 'C:\\Documents and Settings'] }

        [
          { input: '', expected: nil },
          { input: 'cd  ', expected: ['cd  C:\\\\$Recycle.Bin', 'cd  C:\\\\Program\\ Files\\ (x86)', 'cd  C:\\\\Program\\ Files', 'cd  C:\\\\Documents\\ and\\ Settings'] },
          { input: 'cd  C:', expected: ['cd  C:\\\\$Recycle.Bin', 'cd  C:\\\\Program\\ Files\\ (x86)', 'cd  C:\\\\Program\\ Files', 'cd  C:\\\\Documents\\ and\\ Settings'] },
          { input: "cd  'C:\\Progra", expected: ["cd  'C:\\Program Files (x86)'", "cd  'C:\\Program Files'"] },
          { input: 'cd  "C:\\Program"', expected: ['cd  "C:\\Program Files (x86)"', 'cd  "C:\\Program Files"'] },
          { input: "cd  'C:\\Program Files", expected: ["cd  'C:\\Program Files (x86)'", "cd  'C:\\Program Files'"] },
          { input: "cd  'C:\\Program\\ Files", expected: [] },
          { input: "cd  'C:\\Program\\\\ Files", expected: [] },
          { input: 'cd  C:\\\\Program\\ Files', expected: ['cd  C:\\\\Program\\ Files\\ (x86)', 'cd  C:\\\\Program\\ Files'] },
        ].each do |test|
          it "provides completion for #{test[:input].inspect}" do
            expect(subject.tab_complete(test[:input])).to eql(test[:expected])
          end
        end
      end
    end
  end

  describe '#shellsplitex' do
    [
      {
        input: '',
        expected: {
          tokens: [
          ]
        }
      },

      {
        input: '        ',
        focus: true,
        expected: {
          tokens: [
          ]
        }
      },

      {
        input: 'foo       bar',
        focus: true,
        expected: {
          tokens: [
            { begin: 0, value: 'foo', quote: nil },
            { begin: 10, value: 'bar', quote: nil }
          ]
        }
      },

      {
        input: 'dir',
        expected: {
          tokens: [
            { begin: 0, value: 'dir', quote: nil }
          ]
        }
      },

      {
        input: 'dir "/"',
        expected: {
          tokens: [
            { begin: 0, value: 'dir', quote: nil },
            { begin: 4, value: '/', quote: '"' }
          ]
        }
      },

      {
        input: 'dir "/',
        expected: {
          tokens: [
            { begin: 0, value: 'dir', quote: nil },
            { begin: 4, value: '/', quote: '"' }
          ]
        }
      },

      {
        input: 'dir "/Program',
        expected: {
          tokens: [
            { begin: 0, value: 'dir', quote: nil },
            { begin: 4, value: '/Program', quote: '"' }
          ]
        }
      },

      {
        input: 'dir "/Program/',
        expected: {
          tokens: [
            { begin: 0, value: 'dir', quote: nil },
            { begin: 4, value: '/Program/', quote: '"' }
          ]
        }
      },

      {
        input: 'dir C:\\Pro',
        expected: {
          tokens: [
            { begin: 0, value: 'dir', quote: nil },
            { begin: 4, value: 'C:Pro', quote: nil }
          ]
        }
      },

      {
        input: 'dir "C:\\Pro"',
        expected: {
          tokens: [
            { begin: 0, value: 'dir', quote: nil },
            { begin: 4, value: 'C:\\Pro', quote: '"' }
          ]
        }
      },

      {
        input: "dir 'C:\\Pro'",
        expected: {
          tokens: [
            { begin: 0, value: 'dir', quote: nil },
            { begin: 4, value: 'C:\\Pro', quote: "'" }
          ]
        }
      },

      {
        input: "dir 'C:\\ProgramData\\jim\\bob.rb'",
        expected: {
          tokens: [
            { begin: 0, value: 'dir', quote: nil },
            { begin: 4, value: 'C:\\ProgramData\\jim\\bob.rb', quote: "'" }
          ]
        }
      },

      {
        input: "dir 'C:\\ProgramData\\jim\\'",
        expected: {
          tokens: [
            { begin: 0, value: 'dir', quote: nil },
            { begin: 4, value: 'C:\\ProgramData\\jim\\', quote: "'" }
          ]
        }
      },

      {
        input: 'dir "C:\\Pro',
        expected: {
          tokens: [
            { begin: 0, value: 'dir', quote: nil },
            { begin: 4, value: 'C:\\Pro', quote: '"' }
          ]
        }
      },

      {
        input: 'dir "C: \\Pro',
        expected: {
          tokens: [
            { begin: 0, value: 'dir', quote: nil },
            { begin: 4, value: 'C: \\Pro', quote: '"' }
          ]
        }
      },

      {
        input: 'dir "C:\\Program F',
        expected: {
          tokens: [
            { begin: 0, value: 'dir', quote: nil },
            { begin: 4, value: 'C:\\Program F', quote: '"' },
          ]
        }
      },

      {
        input: 'cd  C:\\\\Program\\ F',
        expected: {
          tokens: [
            { begin: 0, value: 'cd', quote: nil },
            { begin: 4, value: 'C:\\Program F', quote: nil },
          ]
        }
      },

      {
        input: 'cd  "C:\\Program F',
        expected: {
          tokens: [
            { begin: 0, value: 'cd', quote: nil },
            { begin: 4, value: 'C:\\Program F', quote: '"' },
          ]
        }
      },

      {
        input: "cd  'C:\\\\Program F",
        expected: {
          tokens: [
            { begin: 0, value: 'cd', quote: nil },
            { begin: 4, value: 'C:\\Program F', quote: "'" },
          ]
        }
      },

      {
        input: "cd  'Progra",
        expected: {
          tokens: [
            { begin: 0, value: 'cd', quote: nil },
            { begin: 4, value: 'Progra', quote: "'" },
          ]
        }
      },

      {
        input: 'pass=a\\ b\\ c user',
        expected: {
          tokens: [
            { begin: 0, value: 'pass=a b c', quote: nil },
            { begin: 13, value: 'user', quote: nil },
          ]
        }
      },

      {
        input: "'pass=a b' username=\"",
        expected: {
          tokens: [
            { begin: 0, value: 'pass=a b', quote: "'" },
            { begin: 11, value: 'username=', quote: '"' },
          ]
        }
      },

      {
        input: "pass='a b' user",
        expected: {
          tokens: [
            { begin: 0, value: 'pass=a b', quote: "'" },
            { begin: 11, value: 'user', quote: nil },
          ]
        }
      },
    ].each do |test|
      it "correctly parses #{test[:input]}" do
        expect(subject.shellsplitex(test[:input])).to eql(test[:expected])
      end
    end
  end
end

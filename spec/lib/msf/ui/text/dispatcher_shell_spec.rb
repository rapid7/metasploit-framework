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

  let(:mock_dispatcher) do
    dispatcher = double :mock_dispatcher
    allow(dispatcher).to receive(:tab_complete_helper) do |_current_word, _preceding_words|
      ['username=']
    end
    dispatcher
  end

  describe '#tab_complete' do
    let(:dispatcher_stack) do
      [
        mock_dispatcher
      ]
    end

    before(:each) do
      allow(subject).to receive(:dispatcher_stack).and_return(dispatcher_stack)
    end

    [
      { input: '', expected: nil },
      { input: '      ', expected: ['      username='] },
      { input: '      u', expected: ['      username='] },
      { input: 'password=abc user', expected: ['password=abc username='] },
      { input: 'password=a\\ b\\ c user', expected: ['password=a\\ b\\ c username='] },
      { input: "'password=a b c' user", expected: ["'password=a b c' username="] },
      { input: "password='a b c' user", expected: ["password='a b c' username="] },
      { input: "password='a b c'       user", expected: ["password='a b c'       username="] },
      { input: 'username=', expected: ['username='] },
      { input: 'password=abc ', expected: ['password=abc username='] }
    ].each do |test|
      it "provides completion for #{test[:input].inspect}" do
        expect(subject.tab_complete(test[:input])).to eql(test[:expected])
      end
    end
  end

  # Tests added to verify regex correctly returns correct values in various situations
  describe '#shellsplitex' do
    [
      {
        input: '',
        expected: {
          unbalanced_quote: nil,
          tokens: [
          ]
        }
      },

      {
        input: '        ',
        focus: true,
        expected: {
          unbalanced_quote: nil,
          tokens: [
          ]
        }
      },

      {
        input: 'foo       bar',
        focus: true,
        expected: {
          unbalanced_quote: nil,
          tokens: [
            { begin: 0, value: 'foo' },
            { begin: 10, value: 'bar' }
          ]
        }
      },

      {
        input: 'dir',
        expected: {
          unbalanced_quote: nil,
          tokens: [
            { begin: 0, value: 'dir' }
          ]
        }
      },

      {
        input: 'dir "/"',
        expected: {
          unbalanced_quote: nil,
          tokens: [
            { begin: 0, value: 'dir' },
            { begin: 4, value: '/' }
          ]
        }
      },

      {
        input: 'dir "/',
        expected: {
          unbalanced_quote: '"',
          tokens: [
            { begin: 0, value: 'dir' },
            { begin: 4, value: '/' }
          ]
        }
      },

      {
        input: 'dir "/Program',
        expected: {
          unbalanced_quote: '"',
          tokens: [
            { begin: 0, value: 'dir' },
            { begin: 4, value: '/Program' }
          ]
        }
      },

      {
        input: 'dir "/Program/',
        expected: {
          unbalanced_quote: '"',
          tokens: [
            { begin: 0, value: 'dir' },
            { begin: 4, value: '/Program/' }
          ]
        }
      },

      {
        input: 'dir C:\\Pro',
        expected: {
          unbalanced_quote: nil,
          tokens: [
            { begin: 0, value: 'dir' },
            { begin: 4, value: 'C:Pro' }
          ]
        }
      },

      {
        input: 'dir "C:\\Pro"',
        expected: {
          unbalanced_quote: nil,
          tokens: [
            { begin: 0, value: 'dir' },
            { begin: 4, value: 'C:\\Pro' }
          ]
        }
      },

      {
        input: "dir 'C:\\Pro'",
        expected: {
          unbalanced_quote: nil,
          tokens: [
            { begin: 0, value: 'dir' },
            { begin: 4, value: 'C:\\Pro' }
          ]
        }
      },

      {
        input: "dir 'C:\\ProgramData\\jim\\bob.rb'",
        expected: {
          unbalanced_quote: nil,
          tokens: [
            { begin: 0, value: 'dir' },
            { begin: 4, value: 'C:\\ProgramData\\jim\\bob.rb' }
          ]
        }
      },

      {
        input: "dir 'C:\\ProgramData\\jim\\'",
        expected: {
          unbalanced_quote: nil,
          tokens: [
            { begin: 0, value: 'dir' },
            { begin: 4, value: 'C:\\ProgramData\\jim\\' }
          ]
        }
      },

      {
        input: 'dir "C:\\Pro',
        expected: {
          unbalanced_quote: '"',
          tokens: [
            { begin: 0, value: 'dir' },
            { begin: 4, value: 'C:\\Pro' }
          ]
        }
      },

      {
        input: 'dir "C: \\Pro',
        expected: {
          unbalanced_quote: '"',
          tokens: [
            { begin: 0, value: 'dir' },
            { begin: 4, value: 'C: \\Pro' }
          ]
        }
      },

      {
        input: 'dir "C:\\Program F',
        expected: {
          unbalanced_quote: '"',
          tokens: [
            { begin: 0, value: 'dir' },
            { begin: 4, value: 'C:\\Program F' },
          ]
        }
      },

      {
        input: 'pass=a\\ b\\ c user',
        expected: {
          unbalanced_quote: nil,
          tokens: [
            { begin: 0, value: 'pass=a b c' },
            { begin: 13, value: 'user' },
          ]
        }
      },

      {
        input: "'pass=a b' username=\"",
        expected: {
          unbalanced_quote: '"',
          tokens: [
            { begin: 0, value: 'pass=a b' },
            { begin: 11, value: 'username=' },
          ]
        }
      },

      {
        input: "pass='a b' user",
        expected: {
          unbalanced_quote: nil,
          tokens: [
            { begin: 0, value: 'pass=a b' },
            { begin: 11, value: 'user' },
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

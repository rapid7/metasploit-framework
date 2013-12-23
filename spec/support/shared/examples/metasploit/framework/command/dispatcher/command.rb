shared_examples_for 'Metasploit::Framework::Command::Dispatcher.command' do |name, options={}|
  options.assert_valid_keys(:klass)
  klass = options.fetch(:klass)

  cmd_method_name = "cmd_#{name}"

  context cmd_method_name do
    include_context 'output'

    subject do
      core.send(cmd_method_name, *arguments)
    end

    let(:arguments) do
      [
          'arguments',
          'to',
          'command'
      ]
    end

    it "creates #{klass} with :dispatcher" do
      klass.should_receive(:new).with(
          hash_including(
              dispatcher: core
          )
      ).and_call_original

      quietly
    end

    it "creates #{klass} with args as :words" do
      klass.should_receive(:new).with(
          hash_including(
              words: arguments
          )
      ).and_call_original

      quietly
    end

    it "runs the #{klass}" do
      klass.any_instance.should_receive(:run)

      quietly
    end
  end

  cmd_help_method_name = "#{cmd_method_name}_help"

  context "#{cmd_help_method_name}" do
    include_context 'output'

    subject do
      core.send(cmd_help_method_name)
    end

    it "calls #{cmd_method_name}('--help')" do
      core.should_receive(cmd_method_name).with('--help').and_call_original

      quietly
    end
  end

  cmd_tabs_method_name = "#{cmd_method_name}_tabs"

  context cmd_tabs_method_name do
    subject do
      core.send(cmd_tabs_method_name, partial_word, words)
    end

    let(:partial_word) do
      'partial_wor'
    end

    let(:words) do
      [
          'words',
          'for',
          'command'
      ]
    end

    it "assumes first word of words is command name and does not pass it to #{klass}.new" do
      _words_head, *words_tail = words

      klass.should_receive(:new).with(
          hash_including(
              words: words_tail
          )
      ).and_call_original

      subject
    end

    it "passes :dispatcher to #{klass}.new" do
      klass.should_receive(:new).with(
          hash_including(
              dispatcher: core
          )
      ).and_call_original

      subject
    end

    it "passes :partial_word to #{klass}.new" do
      klass.should_receive(:new).with(
          hash_including(
              partial_word: partial_word
          )
      ).and_call_original

      subject
    end

    it "uses #tab_completions on #{klass}" do
      tab_completions = double("tab_completions")

      klass.any_instance.should_receive(:tab_completions).and_return(tab_completions)
      subject.should == tab_completions
    end
  end
end
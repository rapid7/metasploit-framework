shared_examples_for 'Msf::Ui::Console::CommandDispatcher::Core::Search' do
  context '#cmd_search' do
    include_context 'output'

    subject(:cmd_search) do
      core.cmd_search(*arguments)
    end

    let(:arguments) do
      [
          'arguments',
          'to',
          'search'
      ]
    end

    it 'creates Metasploit::Framework::Command::Search with dispatcher' do
      Metasploit::Framework::Command::Search.should_receive(:new).with(
          hash_including(
              dispatcher: core

          )
      ).and_call_original

      quietly
    end

    it 'creates Metasploit::Framework::Command::Search with args as words' do
      Metasploit::Framework::Command::Search.should_receive(:new).with(
          hash_including(
              words: arguments
          )
      ).and_call_original

      quietly
    end

    it 'should run the Metasploit::Framework::Command::Search' do
      Metasploit::Framework::Command::Search.any_instance.should_receive(:run)

      quietly
    end
  end

  context '#cmd_search_help' do
    include_context 'output'

    subject(:cmd_search_help) do
      core.cmd_search_help
    end

    it "should call #cmd_search('--help')" do
      core.should_receive(:cmd_search).with('--help').and_call_original

      quietly
    end
  end

  context '#cmd_search_tabs' do
    subject(:cmd_search_tabs) do
      core.cmd_search_tabs(partial_word, words)
    end

    let(:words) do
      [
          'search',
          'for',
          'modules'
      ]
    end

    let(:partial_word) do
      'partial_word'
    end

    it 'assumes first word of words is command name and does not pass it to Metasploit::Framework::Command::Search.new' do
      _words_head, *words_tail = words

      Metasploit::Framework::Command::Search.should_receive(:new).with(
          hash_including(
              words: words_tail
          )
      ).and_call_original

      cmd_search_tabs
    end

    it 'passes dispatcher to Metasploit::Framework::Command::Search.new' do
      Metasploit::Framework::Command::Search.should_receive(:new).with(
          hash_including(
              dispatcher: core
          )
      ).and_call_original

      cmd_search_tabs
    end

    it 'passes partial_word to Metasploit::Framework::Command::Search.new' do
      Metasploit::Framework::Command::Search.should_receive(:new).with(
          hash_including(
              partial_word: partial_word
          )
      ).and_call_original

      cmd_search_tabs
    end

    it 'should use #tab_completions on Metasploit::Framework::Command::Search' do
      tab_completions = double('#tab_completions')

      Metasploit::Framework::Command::Search.any_instance.should_receive(:tab_completions).and_return(tab_completions)
      cmd_search_tabs.should == tab_completions
    end
  end
end
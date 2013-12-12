shared_examples_for 'Metasploit::Framework::Command::Search::Help::TabCompletion' do
  context '#blank_tab_completions' do
    subject(:blank_tab_completions) do
      command.blank_tab_completions
    end

    it { should == [] }
  end

  context '#partial_tab_completions' do
    subject(:partial_tab_completions) do
      command.partial_tab_completions
    end

    it { should == [] }
  end
end
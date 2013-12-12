shared_examples_for 'Metasploit::Framework::Command::TabCompletion' do
  context '#partial_word' do
    subject(:partial_word) do
      command.partial_word
    end

    context 'default' do
      it { should be_nil }
    end

    context 'with value' do
      #
      # lets
      #

      let(:expected_partial_word) do
        double('#partial_word')
      end

      #
      # Callbacks
      #

      before(:each) do
        command.partial_word = expected_partial_word
      end

      it 'should use set value' do
        partial_word.should == expected_partial_word
      end
    end
  end

  context '#tab_completions' do
    subject(:tab_completions) do
      command.tab_completions
    end

    before(:each) do
      command.stub(
          blank_tab_completions: nil,
          parse_words: nil,
          partial_tab_completions: nil
      )
    end

    it 'should #parse_words first' do
      command.should_receive(:parse_words)

      tab_completions
    end

    context 'with partial_word' do
      #
      # lets
      #

      let(:partial_word) do
        'not_blank'
      end

      #
      # Callbacks
      #

      before(:each) do
        command.partial_word = partial_word
      end

      it 'should call #partial_tab_completions' do
        command.should_receive(:partial_tab_completions)

        tab_completions
      end
    end

    context 'without partial_word' do
      it 'should call #blank_tab_completions' do
        command.should_receive(:blank_tab_completions)

        tab_completions
      end
    end
  end
end
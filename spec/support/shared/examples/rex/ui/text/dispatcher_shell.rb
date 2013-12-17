shared_examples_for 'Rex::Ui::Text::DispatcherShell' do
  context 'CONSTANTS' do
    context 'TRAILING_SPACE_REGEXP' do
      subject(:trailing_space_regexp) do
        described_class::TRAILING_SPACE_REGEXP
      end

      it { should == /\s+$/ }
    end
  end

  context 'shell_words' do
    subject(:shell_words) do
      described_class.shell_words(line)
    end

    let(:line) do
      'a line'
    end

    it 'should call Shellwords.split' do
      Shellwords.should_receive(:split).with(line)

      shell_words
    end

    context 'with unclosed double quote' do
      context 'that is repairable' do
        let(:line) do
          'this has a repairable "unclosed double quote'
        end

        it 'should attempt repair by adding a double quote to the end' do
          shell_words.should == [
              'this',
              'has',
              'a',
              'repairable',
              'unclosed double quote'
          ]
        end
      end

      context 'that is not repairable' do
        let(:line) do
          'this has an \'unrepairable "unclosed double quote'
        end

        specify {
          expect {
            shell_words
          }.to raise_error(ArgumentError)
        }
      end
    end
  end

  context '#tab_complete' do
    include_context 'output'

    subject(:tab_complete) do
      dispatcher_shell.tab_complete(line)
    end

    context 'with unrepairable unclosed double quote' do
      #
      # lets
      #

      let(:line) do
        'this has an \'unrepairable "unclosed double quote'
      end

      #
      # Callbacks
      #

      around(:each) do |example|
        Kernel.quietly {
          example.run
        }
      end

      it 'prints error' do
        dispatcher_shell.should_receive(:print_error).with(
            "ArgumentError: Unmatched double quote: \"this has an 'unrepairable \\\"unclosed double quote\\\"\""
        )

        tab_complete
      end

      it { should == [] }
    end

    context 'with trailing space' do
      let(:line) do
        "line with trailing space "
      end

      it '#tab_words should contain all words' do
        tab_complete

        dispatcher_shell.tab_words.should == ['line', 'with', 'trailing', 'space']
      end

      it 'passes empty string to #tab_complet_stub' do
        dispatcher_shell.should_receive(:tab_complete_stub).with('')

        tab_complete
      end
    end

    context 'with escaped space' do
      let(:line) do
        'line containing an escaped\ space'
      end

      it 'should keep escapement' do
        dispatcher_shell.should_receive(:tab_complete_stub).with('escaped\ space')

        quietly

        dispatcher_shell.tab_words.should == ['line', 'containing', 'an']
      end
    end

    context 'without trailing space' do
      let(:line) do
        'line without trailing space'
      end

      it 'should use last word as partial word' do
        dispatcher_shell.should_receive(:tab_complete_stub).with('space')

        tab_complete
      end
    end
  end
end
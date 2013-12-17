require 'spec_helper'

describe Metasploit::Framework::Command::Search do
  include_context 'Msf::Ui::Console::Driver'

  subject(:command) do
    described_class.new(
        dispatcher: dispatcher,
        partial_word: partial_word,
        words: words
    )
  end

  #
  # lets
  #

  let(:dispatcher) do
    Msf::Ui::Console::CommandDispatcher::Core.new(msf_ui_console_driver)
  end

  let(:partial_word) do
    nil
  end

  let(:words) do
    []
  end

  it_should_behave_like 'Metasploit::Framework::Command::Parent'

  context 'subcommands' do
    it { should have_subcommand(:help).class_name('Metasploit::Framework::Command::Search::Help') }
    it { should have_subcommand(:table).class_name('Metasploit::Framework::Command::Search::Table').default(true) }
  end

  context 'validations' do
    context 'words' do
      subject(:errors) do
        command.errors[:words]
      end

      #
      # lets
      #

      let(:error) do
        "invalid option: #{invalid_option}"
      end

      let(:invalid_option) do
        '-a'
      end

      #
      # callbacks
      #

      before(:each) do
        command.valid?
      end

      context 'with invalid option' do
        let(:words) do
          [
              invalid_option
          ]
        end

        it { should include error }
      end

      context 'without invalid option' do
        it { should_not include error }
      end
    end
  end

  context '#option_parser' do
    subject(:option_parser) do
      command.option_parser
    end

    context 'banner' do
      subject(:banner) do
        option_parser.banner
      end

      it { should == 'Usage: search [options]' }
    end
  end

  context '#parse_words' do
    subject(:parse_words) do
      command.send(:parse_words)
    end

    it 'should pass duplicate of #words to option_parser to parse' do
      command.option_parser.should_receive(:parse!) do |parsed_words|
        parsed_words.should_not be command.words
        parsed_words.should == command.words
      end

      parse_words
    end

    context 'words' do
      #
      # Shared examples
      #

      shared_examples_for 'columns' do |type, option|
        type_method = "#{type}_columns"

        context "with #{option}" do
          #
          # lets
          #

          let(:words) do
            [option]
          end

          #
          # callbacks
          #

          before(:each) do
            parse_words
          end

          context "with column name" do
            let(:column_name) do
              'column_name'
            end

            let(:words) do
              super() + [column_name]
            end

            context 'table subcommand' do
              subject(:subcommand) do
                command.send(:subcommand_by_name)[:table]
              end

              context type_method do
                subject(type_method) do
                  subcommand.send(type_method)
                end

                it 'should include the column name' do
                  send(type_method).any? { |column|
                    column.value == column_name
                  }.should be_true
                end
              end
            end
          end

          context "without column name" do
            let(:partial_word) do
              'partial_word'
            end

            context 'table subcommand' do
              subject(:subcommand) do
                command.send(:subcommand_by_name)[:table]
              end

              context type_method do
                subject(type_method) do
                  subcommand.send(type_method)
                end

                it 'should use #partial_word as the column name' do
                  send(type_method).any? { |column|
                    column.value == partial_word
                  }.should be_true
                end
              end
            end
          end
        end
      end

      shared_examples_for 'help' do |option|
        context "with #{option}" do
          let(:words) do
            [option]
          end

          it 'sets #subcommand_name to :help' do
            parse_words

            command.subcommand_name.should == :help
          end
        end
      end

      it_should_behave_like 'columns', :displayed, '-d'
      it_should_behave_like 'columns', :displayed, '--display'
      it_should_behave_like 'columns', :hidden, '-D'
      it_should_behave_like 'columns', :hidden, '--hide'

      it_should_behave_like 'help', '-h'
      it_should_behave_like 'help', '--help'

      context 'with invalid option' do
        let(:invalid_option) do
          '-a'
        end

        let(:words) do
          [
              invalid_option
          ]
        end

        it 'sets @parse_error' do
          parse_words

          command.instance_variable_get(:@parse_error).should be_a OptionParser::ParseError
        end
      end
    end
  end
end
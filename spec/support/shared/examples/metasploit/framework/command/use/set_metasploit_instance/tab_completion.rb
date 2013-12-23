require 'abbrev'

shared_examples_for 'Metasploit::Framework::Command::Use::SetMetasploitInstance::TabCompletion' do
  context '#blank_tab_completions' do
    subject(:blank_tab_completions) do
      command.blank_tab_completions
    end

    context 'with #words' do
      let(:words) do
        [
            'module/class/full/name'
        ]
      end

      it {
        should be_empty
      }
    end

    context 'without #words' do
      include_context 'database cleaner'

      #
      # lets
      #

      let(:full_names) do
        module_classes.map(&:full_name)
      end

      let(:words) do
        []
      end

      #
      # let!s
      #

      let!(:module_classes) do
        FactoryGirl.create_list(:mdm_module_class, 2)
      end

      it { should include '-h' }
      it { should include '--help' }

      it 'should include all Mdm::Module::Class#full_names' do
        full_names.each do |full_name|
          blank_tab_completions.should include(full_name)
        end
      end
    end
  end

  context '#escaped_partial_word' do
    subject(:escaped_partial_word) do
      command.send(:escaped_partial_word)
    end

    context "with '%'" do
      let(:partial_word) do
        '%'
      end

      it { should == '\%' }
    end

    context "with '_'" do
      let(:partial_word) do
        '_'
      end

      it { should == '\_' }
    end
  end

  context '#partial_tab_completions' do
    subject(:partial_tab_completions) do
      command.partial_tab_completions
    end

    context 'with #words' do
      let(:words) do
        [
            'module/class/full/name'
        ]
      end

      it { should == [] }
    end

    context 'without #words' do
      let(:words) do
        []
      end

      context 'with partial option' do
        let(:partial_word) do
          '-'
        end

        it 'calls option_parser.candidate' do
          command.option_parser.should_receive(:candidate).with(partial_word).and_return([])

          partial_tab_completions
        end

        it { should include '-h' }
        it { should include '--help' }
      end

      context 'without partial option' do
        #
        # lets
        #

        let(:partial_word) do
          'partial/wor'
        end

        #
        # let!s
        #

        let!(:module_classes) do
          FactoryGirl.create_list(:mdm_module_class, 2)
        end

        it 'uses #escaped_partial_word' do
          command.should_receive(:escaped_partial_word).and_call_original

          partial_tab_completions
        end

        context 'with partial Mdm::Module::Class#full_name' do
          let(:abbreviations) do
            abbreviations_by_full_name[full_name]
          end

          let(:abbreviations_by_full_name) do
            abbreviations_by_full_name = Hash.new { |hash, full_name|
              hash[full_name] = []
            }

            full_name_by_abbreviation.each_with_object(abbreviations_by_full_name) { |(abbreviation, full_name), hash|
              hash[full_name] << abbreviation
            }
          end

          let(:full_name) do
            full_names.sample
          end

          let(:full_name_by_abbreviation) do
            full_names.abbrev
          end

          let(:full_names) do
            module_classes.map(&:full_name)
          end

          let(:partial_word) do
            abbreviations.sample
          end

          it 'includes matching full_name' do
            expect(partial_tab_completions).to match_array([full_name])
          end
        end

        context 'without partial Mdm::Module::Class#full_name' do
          let(:partial_word) do
            'not/a/partial/module/class/full/name'
          end

          it { should be_empty }
        end
      end
    end
  end
end
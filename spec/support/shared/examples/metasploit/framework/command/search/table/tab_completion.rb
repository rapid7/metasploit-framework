shared_examples_for 'Metasploit::Framework::Command::Search::Table::TabCompletion' do
  context '#blank_tab_completions' do
    subject(:blank_tab_completions) do
      command.blank_tab_completions
    end

    let(:command) do
      described_class.new(
          parent: parent
      )
    end

    let(:parent) do
      Metasploit::Framework::Command::Search.new(
          dispatcher: dispatcher,
          words: words
      )
    end

    context 'last word' do
      let(:words) do
        [
            last_word
        ]
      end

      context 'with column option name' do
        shared_examples_for 'column_name_tab_completions' do |last_word|
          context "with #{last_word}" do
            let(:last_word) do
              last_word
            end

            it "should call #column_name_table_completions(#{last_word.inspect})" do
              command.should_receive(:column_name_tab_completions).with(last_word)

              blank_tab_completions
            end
          end
        end

        it_should_behave_like 'column_name_tab_completions', '--display'
        it_should_behave_like 'column_name_tab_completions', '--hide'
        it_should_behave_like 'column_name_tab_completions', '-D'
        it_should_behave_like 'column_name_tab_completions', '-d'
      end

      context 'without column option name' do
        let(:last_word) do
          'non_an_option'
        end

        context 'operators' do
          it 'should include all search operators on Mdm::Module::Instance' do
            Mdm::Module::Instance.search_operator_by_name.keys.each do |name|
              blank_tab_completions.should include(name.to_s)
            end
          end
        end

        context 'options' do
          it { should include '--display' }
          it { should include '--hide' }
          it { should include '-D' }
          it { should include '-d' }
        end
      end
    end
  end

  context '#column_name_tab_completions' do
    subject(:column_name_tab_completions) do
      command.send(:column_name_tab_completions, last_word)
    end

    #
    # Shared examples
    #

    shared_examples_for 'columns' do |type, last_word|
      let(:column_names) do
        Metasploit::Framework::Command::Search::Argument::Column.set.to_a
      end

      context "with #{last_word}" do
        let(:last_word) do
          last_word
        end

        context "with ##{type}_columns" do
          #
          # lets
          #

          let(:column) do
            Metasploit::Framework::Command::Search::Argument::Column.new(value: column_name)
          end

          let(:column_name) do
            column_names.sample
          end

          #
          # Callbacks
          #

          before(:each) do
            command.send("#{type}_columns") << column
          end

          it "should remove ##{type}_columns values" do
            column_name_tab_completions.should_not include(column_name)
          end
        end

        context "without ##{type}_columns" do
          before(:each) do
            # have to stub has empty to get rid of default values
            command.stub(:"#{type}_columns" => [])
          end

          it 'should return all column names' do
            expect(column_name_tab_completions).to match_array(column_names)
          end
        end
      end
    end

    it_should_behave_like 'columns', :displayed, '-d'
    it_should_behave_like 'columns', :displayed, '--display'

    it_should_behave_like 'columns', :hidden, '-D'
    it_should_behave_like 'columns', :hidden, '--hide'
  end

  context '#column_option_names' do
    subject(:column_option_names) do
      command.send(:column_option_names)
    end

    it { should include '--display' }
    it { should include '--hide' }
    it { should include '-D' }
    it { should include '-d' }
  end

  context '#operator_tab_completions' do
    subject(:operator_tab_completions) do
      command.send(:operator_tab_completions, operator)
    end

    let(:operator) do
      operators.sample
    end

    let(:operators) do
      Mdm::Module::Instance.search_operator_by_name.values.select { |operator|
        operator.respond_to? :attribute
      }
    end

    context 'with valid #visitor' do
      let(:author_name) do
        FactoryGirl.generate :metasploit_model_author_name
      end

      let(:author_name_partial) do
        author_name[0, author_name_partial_length]
      end

      let(:author_name_partial_length) do
        Random.rand(1 .. author_name.length)
      end

      let(:command) do
        described_class.new(
            formatted_operations: formatted_operations,
            parent: parent
        )
      end

      let(:formatted_operations) do
        [
            # must be valid so hard-coding to known good values
            "#{valid_operator_name}:#{module_type}"
        ]
      end

      let(:module_type) do
        FactoryGirl.generate :metasploit_model_module_type
      end

      let(:valid_operator_name) do
        :'module_class.module_type'
      end

      it 'should start with a valid #visitor' do
        command.visitor.should be_valid
      end

      context 'filtered visitor' do
        context 'with valid' do
          let(:operators) do
            # don't allow operator that is the only operator in visitor as removing that operator would leave no
            # operators in query after filtering
            super().reject { |operator|
              operator.name == valid_operator_name
            }
          end

          it 'should be valid after filtering' do
            filtered_query = command.query.without_operator(operator)
            filtered_visitor = MetasploitDataModels::Search::Visitor::Relation.new(query: filtered_query)

            filtered_visitor.should be_valid
          end

          it "should use filter visitor's visit ActiveRecord::Relation for scope" do
            command.should_receive(:scope_tab_completions) do |options|
              options[:operator].should == operator
              filtered_scope = options[:scope].to_sql
              filtered_scope.should_not == Mdm::Module::Instance.scoped.to_sql
            end

            operator_tab_completions
          end
        end

        context 'with empty query' do
          let(:operator) do
            # query will be empty after filtering because this is the only operator in the query before filtering
            Mdm::Module::Instance.search_operator_by_name[valid_operator_name]
          end

          it 'should use Mdm::Module::Instance.scoped for scope' do
            command.should_receive(:scope_tab_completions) do |options|
              options[:operator].should == operator
              options[:scope].to_sql.should == Mdm::Module::Instance.scoped.to_sql
            end

            operator_tab_completions
          end
        end
      end
    end

    context 'without valid #visitor' do
      context 'with empty query' do
        it 'should use Mdm::Module::Instance.scoped for scope' do
          command.should_receive(:scope_tab_completions).with(
              hash_including(
                  operator: operator,
                  scope: Mdm::Module::Instance.scoped
              )
          )

          operator_tab_completions
        end
      end

      context 'without empty query' do
        let(:command) do
          described_class.new(
              formatted_operations: formatted_operations,
              parent: parent
          )
        end

        let(:formatted_operation) do
          'invalid_operator:invalid_value'
        end

        let(:formatted_operations) do
          [
              formatted_operation
          ]
        end

        let(:query) do
          command.query
        end

        let(:visitor) do
          command.visitor
        end

        it 'should not have valid visitor' do
          visitor.should_not be_valid
        end

        it 'should have operations' do
          query.operations.should_not be_empty
        end

        it { should be_nil }
      end
    end
  end

  context '#partial_tab_completions' do
    subject(:partial_tab_completions) do
      command.partial_tab_completions
    end

    let(:option_parser) do
      parent.option_parser
    end

    let(:parent) do
      Metasploit::Framework::Command::Search.new(
          dispatcher: dispatcher,
          partial_word: partial_word,
          words: words
      )
    end

    let(:partial_word) do
      'partial_word'
    end

    let(:words) do
      []
    end

    it 'should check option parser for candidates' do
      option_parser.should_receive(:candidate).with(partial_word).and_call_original

      partial_tab_completions
    end

    context 'with partial option' do
      #
      # lets
      #

      let(:options) do
        [
            '--display',
            '--hide',
            '-D',
            '-d'
        ]
      end

      # parent needs to be created without partial_word set because partial_word needs to be derived from options_parser
      # and parent -> option_parser
      let(:parent) do
        Metasploit::Framework::Command::Search.new(
            dispatcher: dispatcher,
            words: words
        )
      end

      let(:partial_word) do
        word = options.sample
        partial_length = Random.rand(1...word.length)

        word[0, partial_length]
      end

      #
      # callbacks
      #

      before(:each) do
        # set partial word so it doesn't cause circular dependency in lets
        parent.partial_word = partial_word
      end

      it 'should return option parser candidates' do
        partial_tab_completions.should == option_parser.candidate(partial_word)
      end
    end

    context 'without partial option' do
      #
      # Shared examples
      #

      shared_examples_for 'operator_tab_completions' do
        let(:partial_word) do
          operator_unique_prefixes.sample
        end

        let(:operator) do
          Mdm::Module::Instance.search_operator_by_name[operator_name]
        end

        let(:operator_name) do
          operator_names.sample
        end

        let(:operator_name_by_unique_prefix) do
          operator_names_by_unique_prefix.each_with_object({}) { |(prefix, operator_names), operator_name_by_unique_prefix|
            operator_name_by_unique_prefix[prefix] = operator_names.first
          }
        end

        let(:operator_names_by_unique_prefix) do
          operator_names_by_prefix.select { |_prefix, operator_names|
            operator_names.length == 1
          }
        end

        let(:operator_unique_prefixes) do
          operator_name_by_unique_prefix.each_with_object([]) { |(unique_prefix, operator_name), operator_unique_prefixes|
            if operator_name == operator.name
              operator_unique_prefixes << unique_prefix
            end
          }
        end

        #
        # Callbacks
        #

        before(:each) do
          if operator_unique_prefixes.empty?
            fail "No unique prefixes for operator name (#{operator.name})"
          end
        end

        context 'with association operator' do
          # names are hard-coded so that logic used in code-under-test is not duplicated here
          let(:operator_names) do
            [
                :'actions.name',
                :'architectures.abbreviaiton',
                :'architectures.bits',
                :'architectures.endianness',
                :'architectures.family',
                :'authorities.abbreviation',
                :'authors.name',
                :'email_addresses.domain',
                :'email_addresses.full',
                :'email_addresses.local',
                :'module_class.full_name',
                :'module_class.module_type',
                :'module_class.payload_type',
                :'module_class.reference_name',
                :'platforms.fully_qualified_name',
                :'rank.name',
                :'rank.number',
                :'references.designation',
                :'references.url',
                :'targets.name'
            ]
          end

          it 'should call #operator_tab_completions' do
            command.should_receive(:operator_tab_completions).with(operator)

            partial_tab_completions
          end
        end

        context 'with attribute operator' do
          # names are hard-coded so that logic used in code-under-test is not duplicated here
          let(:operator_names) do
            [
                :description,
                :disclosed_on,
                :license,
                :name,
                :privileged,
                :stance
            ]
          end

          it 'should call #operator_tab_completions' do
            command.should_receive(:operator_tab_completions).with(operator)

            partial_tab_completions
          end
        end

        context 'without association or attribute operator' do
          # names are hard-coded so that logic used in code-under-test is not duplicated here
          let(:operator_names) do
            [
                :app,
                :author,
                :bid,
                :cve,
                :edb,
                # os's entire length is a prefix of osvdb, so have to exclude both or partial column name
                # logic test will fail when os is picked.
                :platform,
                :ref,
                :text
            ]
          end

          it 'should not call #operator_tab_completion' do
            command.should_not_receive(:operator_tab_completions)

            partial_tab_completions
          end
        end
      end

      #
      # lets
      #

      let(:operator_names) do
        Mdm::Module::Instance.search_operator_by_name.keys.map(&:to_s)
      end

      let(:operator_names_by_prefix) do
        # Adapted from https://github.com/ruby/ruby/blob/9a938987cb6b3ed3f0c7735f5b19b10f45694a3f/lib/abbrev.rb#L75-L91
        operator_names_by_prefix = Hash.new { |hash, prefix|
          hash[prefix] = []
        }

        operator_names.each do |operator_name|
          operator_name.size.downto(1) { |length|
            prefix = operator_name[0 ... length]

            operator_names_by_prefix[prefix] << operator_name
          }
        end

        operator_names_by_prefix
      end

      context 'with partial column name' do
        let(:column_option_names) do
          [
              '--display',
              '--hide',
              '-D',
              '-d'
          ]
        end

        let(:last_word) do
          column_option_names.sample
        end

        let(:words) do
          [
              last_word
          ]
        end

        it 'should call #column_name_tab_completions(last_word)' do
          command.should_receive(:column_name_tab_completions).with(last_word)

          partial_tab_completions
        end
      end

      context 'without partial column name' do
        context 'with partial formatted operation' do
          context 'with one operation' do
            it_should_behave_like 'operator_tab_completions'
          end

          context 'with two or more operations' do
            let(:partial_word) do
              "#{operator_name}:"
            end

            let(:operator_name) do
              operator_names.sample
            end

            let(:operator_names) do
              # the authority operators return two operations as they are the intersection of authorities.abbreviation
              # and references.designation
              [
                  :bid,
                  :cve,
                  :edb,
                  :osvdb
              ]
            end

            it { should == [] }
          end
        end

        context 'with partial operator' do
          context 'with matching operator names' do
            context 'with one matching operators' do
              it_should_behave_like 'operator_tab_completions'
            end

            context 'with two or more matching operators' do
              let(:common_prefixes) do
                operator_names_by_prefix.each_with_object([]) do |(prefix, operator_names), common_prefixes|
                  if operator_names.length > 1
                    common_prefixes << prefix
                  end
                end
              end

              let(:partial_word) do
                common_prefixes.sample
              end

              it 'should be matching operator names' do
                operator_names = operator_names_by_prefix[partial_word]

                expect(partial_tab_completions).to match_array(operator_names)
              end
            end
          end

          context 'without matching operator names' do
            it { should == [] }
          end
        end
      end
    end
  end

  context '#scope_tab_completions' do

    subject(:scope_tab_completions) do
      command.send(
          :scope_tab_completions,
          operator: operator,
          scope: scope
      )
    end

    #
    # lets
    #

    let(:target_name) do
      "Target Needs To Be Escaped"
    end

    let(:operator) do
      # hard code operator name so its values can be created in database.
      Mdm::Module::Instance.search_operator_by_name[:'targets.name']
    end

    let(:scope) do
      Mdm::Module::Instance.scoped
    end

    it 'should calculate joins using MetasploitDataModels::Search::Visitor::Joins' do
      MetasploitDataModels::Search::Visitor::Joins.should_receive(:new).and_call_original
      scope.should_receive(:joins).with([:targets]).and_call_original

      scope_tab_completions
    end

    it 'should calculate AREL attribute using MetasploitDataModels::Search::Visitor::Attribute' do
      MetasploitDataModels::Search::Visitor::Attribute.should_receive(:new).and_call_original
      ActiveRecord::Relation.any_instance.should_receive(:pluck).with('"module_targets"."name"').and_call_original

      scope_tab_completions
    end

    it 'should use ActiveRecord::Relation#pluck to get values for attribute' do
      ActiveRecord::Relation.any_instance.should_receive(:pluck).and_return([])

      scope_tab_completions
    end

    context 'with boolean values' do
      include_context 'database cleaner'

      #
      # lets
      #

      let(:operator) do
        Mdm::Module::Instance.search_operator_by_name[:privileged]
      end

      let(:privilegeds) do
        [
            false,
            true
        ]
      end

      #
      # let!s
      #

      let!(:module_instance_by_privileged) do
        privilegeds.each_with_object({}) { |privileged, hash|
          hash[privileged] = FactoryGirl.create(
              :mdm_module_instance,
              privileged: privileged
          )
        }
      end

      it 'returns Booleans as Strings' do
        boolean_strings = scope_tab_completions.collect { |completion|
          completion[/false|true/]
        }

        expect(boolean_strings).to match_array(['false', 'true'])
      end
    end

    context 'with null values' do
      include_context 'database cleaner'

      let(:architecture_with_bits) do
        Mdm::Architecture.where(Mdm::Architecture.arel_table[:bits].not_eq(nil)).first
      end

      let(:architecture_without_bits) do
        Mdm::Architecture.where(Mdm::Architecture.arel_table[:bits].eq(nil)).first
      end

      let(:architectures) do
        [
            architecture_with_bits,
            architecture_without_bits
        ]
      end

      let(:module_architectures_module_types) do
        Metasploit::Model::Module::Instance.module_types_that_allow(:module_architectures)
      end

      let(:module_class) do
        FactoryGirl.create(
            :mdm_module_class,
            module_type: module_type
        )
      end

      let(:module_instance) do
        FactoryGirl.build(
            :mdm_module_instance,
            module_class: module_class,
            module_architectures_length: 0
        ).tap { |module_instance|
          architectures.each do |architecture|
            module_instance.module_architectures.build(
                architecture: architecture
            )
          end
        }
      end

      let(:module_type) do
        module_types.sample
      end

      let(:module_types) do
        # want to be able to make the module architecture directly and not through a target
        module_architectures_module_types - targets_module_types
      end

      let(:operator) do
        Mdm::Module::Instance.search_operator_by_name[:'architectures.bits']
      end

      let(:targets_module_types) do
        Metasploit::Model::Module::Instance.module_types_that_allow(:targets)
      end

      #
      # Callbacks
      #

      before(:each) do
        module_instance.save!
      end

      it 'should not return nulls' do
        scope_tab_completions.length.should == 1
      end

      it 'should return non-nulls' do
        scope_tab_completions.should include("#{operator.name}:#{architecture_with_bits.bits}")
      end
    end

    context 'with duplicate values' do
      include_context 'database cleaner'
      #
      # lets
      #

      let(:count) do
        2
      end

      let(:module_instances) do
        module_classes.collect { |module_class|
          FactoryGirl.build(
              :mdm_module_instance,
              module_class: module_class,
              # turn off factory built targets so target name can be set
              targets_length: 0
          ).tap { |module_instance|
            FactoryGirl.build(
                :mdm_module_target,
                module_instance: module_instance,
                name: target_name
            )
          }
        }
      end

      #
      # let!s
      #

      let!(:module_classes) do
        FactoryGirl.create_list(
            :mdm_module_class,
            count,
            # need to be type that has targets
            module_type: 'exploit'
        )
      end

      #
      # Callbacks
      #

      before(:each) do
        module_instances.each(&:save!)
      end

      it 'should have multiple, duplicate values for attribute' do
        values = Mdm::Module::Instance.joins(:targets).pluck('module_targets.name')

        values.length.should > values.uniq.length
      end

      it 'should return unique values for attribute' do
        scope_tab_completions.length.should == 1
      end

      it 'should return formatted operations' do
        scope_tab_completions.all? { |completion|
          completion.start_with? "#{operator.name}:"
        }.should be_true
      end

      it 'should shell escape values' do
        scope_tab_completions.all? { |completion|
          completion.include? Shellwords.escape(target_name)
        }.should be_true
      end
    end

    context 'with reserved word table name' do
      include_context 'database cleaner'

      let(:operator) do
        Mdm::Module::Instance.search_operator_by_name[:'references.designation']
      end

      let(:operator_name) do
        operator_names.sample
      end

      let(:operator_names) do
        # REFERENCES is a reserved word in postgresql.  It is used to declared foreign key constraints.  It must be
        # quoted when used as a table or column name.
        [
            :'references.designation',
            :'references.url'
        ]
      end

      specify {
        expect {
          scope_tab_completions
        }.not_to raise_error
      }
    end
  end
end

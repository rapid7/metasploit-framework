RSpec.describe Metasploit::Model::Association::Tree do
  context 'expand' do
    subject(:expand) {
      described_class.expand(associations)
    }

    context 'with Array<Hash>' do
      let(:associations) {
        [
            {
                first_parent: :first_child
            },
            {
                second_parent: :second_child
            }
        ]
      }

      it 'merges hashes' do
        expect(expand).to have_key(:first_parent)

        first_child_tree = expand[:first_parent]

        expect(first_child_tree).to have_key(:first_child)
        expect(first_child_tree[:first_child]).to be_nil

        expect(expand).to have_key(:second_parent)

        second_child_tree = expand[:second_parent]

        expect(second_child_tree).to have_key(:second_child)
        expect(second_child_tree[:second_child]).to be_nil
      end
    end


    context 'with Array<Symbol>' do
      let(:associations) {
        [
            :first,
            :second
        ]
      }

      it 'expands to Hash{Symbol => nil}' do
        expect(expand).to have_key(:first)
        expect(expand[:first]).to be_nil

        expect(expand).to have_key(:second)
        expect(expand[:second]).to be_nil
      end
    end

    context 'with Hash<Symbol>' do
      let(:associations) {
        {
            parent: :child
        }
      }

      it 'expands to Hash{Symbol => Hash{Symbol => nil}}' do
        expect(expand).to have_key(:parent)

        child_tree = expand[:parent]

        expect(child_tree).to have_key(:child)
        expect(child_tree[:child]).to be_nil
      end
    end

    context 'with Symbol' do
      let(:associations) {
        :symbol
      }

      it 'expands to Hash{Symbol => nil}' do
        expect(expand).to have_key(:symbol)
        expect(expand[:symbol]).to be_nil
      end
    end
  end

  context 'merge' do
    subject(:merge) {
      described_class.merge(first, second)
    }

    context 'first' do
      context 'with nil' do
        let(:first) {
          nil
        }

        context 'second' do
          context 'with nil' do
            let(:second) {
              nil
            }

            it { is_expected.to be_nil }
          end

          context 'without nil' do
            let(:second) {
              double('second')
            }

            it 'returns second' do
              expect(merge).to eq(second)
            end
          end
        end
      end

      context 'without nil' do
        let(:first) {
          {
              common: {
                  first_common_child: nil
              },
              first: {
                  first_child: nil
              }
          }
        }

        context 'second' do
          context 'with nil' do
            let(:second) {
              nil
            }

            it 'returns first' do
              expect(merge).to eq(first)
            end
          end

          context 'without nil' do
            let(:second) {
              {
                  common: {
                      second_common_child: nil
                  },
                  second: {
                      second_child: nil
                  }
              }
            }

            it 'merges trees under common keys' do
              expect(merge).to have_key(:common)

              common_tree = merge[:common]

              expect(common_tree).to have_key(:first_common_child)
              expect(common_tree[:first_common_child]).to be_nil
              expect(common_tree).to have_key(:second_common_child)
              expect(common_tree[:second_common_child]).to be_nil
            end

            it 'reuses uncommon keys' do
              expect(merge[:first]).to eq(first[:first])
              expect(merge[:second]).to eq(second[:second])
            end
          end
        end
      end
    end
  end

  context 'operators' do
    subject(:operators) {
      described_class.operators(
          expanded,
          class: klass
      )
    }

    let(:near_class) {
      Class.new {
        include Metasploit::Model::Search

        search_attribute :near_boolean,
                         type: :boolean
        search_attribute :near_string,
                         type: :string
      }.tap { |klass|
        stub_const('NearClass', klass)
      }
    }

    let(:klass) {
      near_class = self.near_class

      Class.new do
        include Metasploit::Model::Association

        association :near_classes,
                    class_name: near_class.name
      end
    }

    context 'with Hash{Symbol => nil}' do
      let(:expanded) {
        {
            near_classes: nil
        }
      }

      it 'includes a Metasploit::Model::Search::Operator::Association for each non-association operator on the associated class' do
        near_classes_near_boolean = operators.find { |o| o.name == :'near_classes.near_boolean' }

        expect(near_classes_near_boolean).to be_a Metasploit::Model::Search::Operator::Association
        expect(near_classes_near_boolean.association).to eq(:near_classes)
        expect(near_classes_near_boolean.klass).to eq(klass)

        near_boolean = near_classes_near_boolean.source_operator

        expect(near_boolean).to eq(near_class.search_operator_by_name.fetch(:near_boolean))

        near_classes_near_string = operators.find { |o| o.name == :'near_classes.near_string' }

        expect(near_classes_near_string).to be_a Metasploit::Model::Search::Operator::Association
        expect(near_classes_near_string.association).to eq(:near_classes)
        expect(near_classes_near_string.klass).to eq(klass)

        near_string = near_classes_near_string.source_operator

        expect(near_string).to eq(near_class.search_operator_by_name.fetch(:near_string))
      end
    end

    context 'with Hash{Symbol => Hash}' do
      let(:expanded) {
        {
            near_classes: {
                far_class: nil
            }
        }
      }

      let(:far_class) {
        Class.new {
          include Metasploit::Model::Search

          search_attribute :far_integer,
                           type: :integer
        }.tap { |klass|
          stub_const('FarClass', klass)
        }
      }

      let(:near_class) {
        super().tap { |klass|
          far_class = self.far_class

          klass.class_eval do
            include Metasploit::Model::Association

            association :far_class,
                        class_name: far_class.name
          end
        }
      }

      it 'includes a Metasploit::Model::Search::Operator::Association for each non-association operator on the near class' do
        near_classes_near_boolean = operators.find { |o| o.name == :'near_classes.near_boolean' }

        expect(near_classes_near_boolean).to be_a Metasploit::Model::Search::Operator::Association
        expect(near_classes_near_boolean.association).to eq(:near_classes)
        expect(near_classes_near_boolean.klass).to eq(klass)

        near_boolean = near_classes_near_boolean.source_operator

        expect(near_boolean).to eq(near_class.search_operator_by_name.fetch(:near_boolean))

        near_classes_near_string = operators.find { |o| o.name == :'near_classes.near_string' }

        expect(near_classes_near_string).to be_a Metasploit::Model::Search::Operator::Association
        expect(near_classes_near_string.association).to eq(:near_classes)
        expect(near_classes_near_string.klass).to eq(klass)

        near_string = near_classes_near_string.source_operator

        expect(near_string).to eq(near_class.search_operator_by_name.fetch(:near_string))
      end

      it 'includes Metasploit::Model::Search::Operator::Association for each non-association operator on the far class' do
        near_classes_far_class_far_integer = operators.find { |o| o.name == :'near_classes.far_class.far_integer' }

        expect(near_classes_far_class_far_integer).to be_a Metasploit::Model::Search::Operator::Association
        expect(near_classes_far_class_far_integer.association).to eq(:near_classes)
        expect(near_classes_far_class_far_integer.klass).to eq(klass)

        far_class_far_integer = near_classes_far_class_far_integer.source_operator

        expect(far_class_far_integer).to be_a Metasploit::Model::Search::Operator::Association
        expect(far_class_far_integer.association).to eq(:far_class)
        expect(far_class_far_integer.klass).to eq(near_class)

        far_integer = far_class_far_integer.source_operator

        expect(far_integer).to eq(far_class.search_operator_by_name.fetch(:far_integer))
      end
    end

    context 'with nil' do
      let(:expanded) {
        nil
      }

      it { is_expected.to eq([]) }
    end
  end


  context 'reflect_on_association_on_class' do
    subject(:reflect_on_association_on_class) {
      described_class.reflect_on_association_on_class(association, klass)
    }

    let(:association) {
      :associated_things
    }

    let(:klass) {
      Class.new
    }

    context 'klass' do
      context 'responds to reflect_on_association' do
        let(:klass) {
          super().tap { |klass|
            klass.send(:include, Metasploit::Model::Association)
          }
        }

        context 'with association' do
          #
          # lets
          #

          let(:associated_class) {
            Class.new.tap { |klass|
              stub_const('AssociatedThing', klass)
            }
          }

          let(:klass) {
            super().tap { |klass|
              klass.association association, class_name: associated_class.name
            }
          }

          it 'returns reflection with associated class as klass' do
            expect(reflect_on_association_on_class.klass).to eq(associated_class)
          end
        end

        context 'without association' do
          it 'raises a Metasploit::Model::Association::Error on association and klass' do
            expect {
              reflect_on_association_on_class
            }.to raise_error(Metasploit::Model::Association::Error) { |error|
              expect(error.model).to eq(klass)
              expect(error.name).to eq(association)
            }
          end
        end
      end

      context 'does not respond to reflect_on_association' do
        it 'raises NameError with instructions for using Metasploit::Model::Association' do
          expect {
            reflect_on_association_on_class
          }.to raise_error(NameError) { |error|
            expect(error.message).to include 'Metasploit::Model::Association'
          }
        end
      end
    end
  end
end
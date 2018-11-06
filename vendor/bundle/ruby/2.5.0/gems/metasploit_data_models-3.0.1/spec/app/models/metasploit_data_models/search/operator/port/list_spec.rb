RSpec.describe MetasploitDataModels::Search::Operator::Port::List, type: :model do
  subject(:port_list_operator) {
    described_class.new(
        klass: klass
    )
  }

  let(:klass) {
    Mdm::Service
  }

  context 'CONSTANTS' do
    context 'SEPARATOR' do
      subject(:separator) {
        described_class::SEPARATOR
      }

      it { is_expected.to eq(',') }
    end
  end

  context '#attribute' do
    subject(:attribute) {
      port_list_operator.attribute
    }

    context 'default' do
      it { is_expected.to eq(:port) }
    end

    context 'setter' do
      let(:value) {
        :alternate_port
      }

      #
      # Callbacks
      #

      before(:example) do
        port_list_operator.attribute = value
      end

      it 'sets #attribute' do
        expect(port_list_operator.attribute).to eq(value)
      end
    end
  end

  context '#children' do
    subject(:children) {
      port_list_operator.children(formatted_value)
    }

    context "with ','" do
    end

    context "without ','" do
      context "with '-'" do
        let(:formatted_value) {
          '1-2'
        }

        it 'includes a MetasploitDataModels::Search::Operation::Port::Range' do
          expect(children.map(&:class)).to include(MetasploitDataModels::Search::Operation::Port::Range)
        end

        context 'MetasploitDataModels::Search::Operation::Port::Range' do
          subject(:operation_range) {
            children.first
          }

          context '#operator' do
            subject(:operator) {
              operation_range.operator
            }

            it 'is this MetasploitDataModels::Search::Operator::Port::List' do
              expect(operator).to be(port_list_operator)
            end
          end

          context '#value' do
            subject(:value) {
              operation_range.value
            }

            it { is_expected.to be_a Range }
          end
        end
      end

      context "without '-'" do
        let(:formatted_value) {
          '1'
        }

        it 'includes a MetasploitDataModels::Search::Operation::Port::Number' do
          expect(children.map(&:class)).to include(MetasploitDataModels::Search::Operation::Port::Number)
        end

        context 'MetasploitDataModels::Search::Operation::Port::Number' do
          subject(:operation_range) {
            children.first
          }

          context '#operator' do
            subject(:operator) {
              operation_range.operator
            }

            it 'is this MetasploitDataModels::Search::Operator::Port::List' do
              expect(operator).to be(port_list_operator)
            end
          end

          context '#value' do
            subject(:value) {
              operation_range.value
            }

            it { is_expected.to be_an Integer }
          end
        end
      end
    end
  end

  context '#name' do
    subject(:name) {
      port_list_operator.name
    }

    #
    # lets
    #

    let(:attribute) {
      :alternate_port_list
    }

    #
    # Callbacks
    #

    before(:example) do
      port_list_operator.attribute = attribute
    end

    it 'is #attribute' do
      expect(name).to eq(attribute)
    end
  end

  context 'operator_name' do
    subject(:operator_name) {
      described_class.operator_name
    }

    it { is_expected.to eq('port_list') }
  end
end
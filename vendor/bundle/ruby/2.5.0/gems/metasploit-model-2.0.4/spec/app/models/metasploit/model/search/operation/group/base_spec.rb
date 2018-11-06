RSpec.describe Metasploit::Model::Search::Operation::Group::Base, type: :model do
  subject(:group) do
    described_class.new
  end

  it { is_expected.to be_a Metasploit::Model::Search::Operation::Base }

  context 'validations' do
    context 'children' do
      it { is_expected.to validate_length_of(:children).is_at_least(1).with_short_message('is too short (minimum is 1 child)') }

      context '#children_valid' do
        subject(:children_valid) do
          group.send(:children_valid)
        end

        #
        # let
        #

        let(:error) do
          I18n.translate!(:'errors.messages.invalid')
        end

        let(:group) do
          described_class.new(
              children: children
          )
        end

        context 'with children' do
          #
          # lets
          #

          let(:children) do
            Array.new(2) { |i|
              double("Child #{i}")
            }
          end

          #
          # Callbacks
          #

          context 'with all valid' do
            before(:example) do
              children.each do |child|
                allow(child).to receive(:valid?).and_return(true)
              end
            end

            it 'does not add error on :children' do
              group.valid?

              expect(group.errors[:children]).not_to include(error)
            end
          end

          context 'with later valid' do
            before(:example) do
              allow(children.first).to receive(:valid?).and_return(false)
              allow(children.second).to receive(:valid?).and_return(true)
            end

            it 'does not short-circuit and validates all children' do
              expect(children.second).to receive(:valid?).and_return(true)

              children_valid
            end

            it 'should add error on :children' do
              group.valid?

              expect(group.errors[:children]).to include(error)
            end
          end
        end

        context 'without children' do
          let(:children) do
            []
          end

          it 'does not add error on :children' do
            group.valid?

            expect(group.errors[:children]).not_to include(error)
          end
        end
      end
    end
  end

  context '#children' do
    subject(:children) do
      group.children
    end

    context 'default' do
      it { is_expected.to eq([]) }
    end

    context 'with attribute' do
      let(:expected_children) do
        [
            double('child')
        ]
      end

      let(:group) do
        described_class.new(
            children: expected_children
        )
      end

      it 'is the value passed with :children to #new' do
        expect(children).to eq(expected_children)
      end
    end
  end
end
RSpec.describe MetasploitDataModels::Search::Operator::Multitext, type: :model do
  subject(:multitext_operator) {
    described_class.new(
        attributes
    )
  }

  let(:attributes) {
    {}
  }

  context 'validations' do
    it { is_expected.to validate_length_of(:operator_names).is_at_least(2) }
    it { is_expected.to validate_presence_of :name }
  end

  context '#children' do
    subject(:children) {
      multitext_operator.children(formatted_value)
    }

    let(:attributes) {
      {
          klass: klass,
          operator_names: operator_names
      }
    }

    let(:klass) {
      Mdm::Host
    }

    let(:operator_names) {
      [
          :os_flavor,
          :os_name,
          :os_sp
      ]
    }

    context 'with nil' do
      let(:formatted_value) {
        nil
      }

      it { is_expected.to eq([]) }
    end

    context 'with empty String' do
      let(:formatted_value) {
        ''
      }

      it { is_expected.to eq([]) }
    end

    context 'without quotes' do
      let(:formatted_value) {
        words.join(' ')
      }

      let(:words) {
        %w{multiple words}
      }

      it 'generates a union for each word' do
        children.each_with_index do |child, index|
          expect(child).to be_a Metasploit::Model::Search::Operation::Group::Union

          child.children.each do |grandchild|
            expect(grandchild.value).to eq(words[index])
          end
        end
      end
    end

    context 'with quotes' do
      let(:formatted_value) {
        %Q{"quoted words"}
      }

      it 'generates a single union for quoted words as a single argument' do
        expect(children.length).to eq(1)

        child = children.first

        expect(child).to be_a Metasploit::Model::Search::Operation::Group::Union

        child.children.each do |grandchild|
          expect(grandchild.value).to eq('quoted words')
        end
      end
    end
  end

  context '#name' do
    subject(:name) {
      multitext_operator.name
    }

    context 'default' do
      it { is_expected.to be_nil }
    end

    context 'setter' do
      let(:new_name) {
        :new_name
      }

      it 'sets #name' do
        expect {
          multitext_operator.name = new_name
        }.to change(multitext_operator, :name).to(new_name)
      end
    end
  end

  context '#operator_names' do
    subject(:operator_names) {
      multitext_operator.operator_names
    }

    context 'default' do
      it { is_expected.to eq([]) }
    end
  end

  context '#operators' do
    subject(:operators) {
      multitext_operator.operators
    }

    let(:attributes) {
      {
          klass: klass,
          operator_names: operator_names
      }
    }

    let(:klass) {
      Mdm::Host
    }

    let(:operator_names) {
      [
          :os_flavor,
          :os_name,
          :os_sp
      ]
    }

    it 'looks up all operators by name using #operator' do
      operator_names.each do |operator_name|
        expect(multitext_operator).to receive(:operator).with(operator_name).and_call_original
      end

      operators
    end
  end
end
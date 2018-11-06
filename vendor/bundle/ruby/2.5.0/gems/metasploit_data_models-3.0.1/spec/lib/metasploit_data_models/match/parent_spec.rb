RSpec.describe MetasploitDataModels::Match::Parent do
  let(:including_class) {
    described_class = self.described_class

    Class.new {
      include described_class
    }
  }

  let(:including_class_instance) {
    including_class.new
  }

  context 'match_child_names' do
    subject(:match_child_names) {
      including_class.match_child_names
    }

    context 'default' do
      it { is_expected.to eq([]) }
    end
  end

  context '#match_child' do
    subject(:match_child) {
      including_class_instance.match_child(formatted_value)
    }

    #
    # lets
    #

    let(:number_child_class) {
      Class.new(Metasploit::Model::Base) do
        extend MetasploitDataModels::Match::Child

        attr_accessor :value
      end
    }

    let(:range_child_class) {
      Class.new(Metasploit::Model::Base) do
        extend MetasploitDataModels::Match::Child

        attr_accessor :value
      end
    }

    #
    # Callbacks
    #

    before(:example) do
      stub_const('NumberChild', number_child_class)
      stub_const('NumberChild::REGEXP', /\d+/)

      stub_const('RangeChild', range_child_class)
      stub_const('RangeChild::REGEXP', /\d+-\d+/)

      including_class.class_eval do
        match_children_named %w{NumberChild RangeChild}
      end
    end

    context 'with matching child class' do
      let(:formatted_value) {
        '1-10'
      }

      it 'returns instance of matching child class' do
        expect(match_child).to be_a RangeChild
      end
    end

    context 'without matching child class' do
      let(:formatted_value) {
        'a-b'
      }

      it 'calls match on all child classes' do
        expect(NumberChild).to receive(:match).with(formatted_value)
        expect(RangeChild).to receive(:match).with(formatted_value)

        match_child
      end

      it { is_expected.to be_nil }
    end
  end

  context 'match_children' do
    subject(:match_children) {
      including_class.match_children
    }

    context 'default' do
      it { is_expected.to eq([]) }
    end

    context 'with class names' do
      #
      # lets
      #

      let(:child_class_names) {
        [
            'ChildOne',
            'ChildTwo'
        ]
      }

      let(:child_classes) {
        child_class_names.map { |child_class_name|
          child_class = Class.new

          stub_const(child_class_name, child_class)

          child_class
        }
      }

      #
      # Callbacks
      #

      before(:example) do
        including_class.match_children_named child_classes.map(&:name)
      end

      it 'includes child Classes' do
        expect(match_children).to match_array(child_classes)
      end
    end
  end

  context 'match_children_named' do
    subject(:match_children_named) {
      including_class.match_children_named child_class_names
    }

    let(:child_class_names) {
      Array.new(2) { |i|
        "ChildClass#{i}"
      }
    }

    it 'sets match_child_names' do
      match_children_named

      expect(including_class.match_child_names).to eq(child_class_names)
    end
  end
end
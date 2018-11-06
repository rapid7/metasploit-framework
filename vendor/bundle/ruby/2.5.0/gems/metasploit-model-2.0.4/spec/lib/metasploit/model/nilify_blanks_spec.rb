RSpec.describe Metasploit::Model::NilifyBlanks do
  let(:base_class) do
    # capture for class_eval scope
    described_class = self.described_class

    Class.new do
      extend ActiveModel::Callbacks
      include ActiveModel::Validations
      include ActiveModel::Validations::Callbacks

      include described_class
    end
  end

  context 'included' do
    let(:base_class) do
      Class.new do
        extend ActiveModel::Callbacks
        include ActiveModel::Validations
        include ActiveModel::Validations::Callbacks
      end
    end

    it 'should register #nilify_blanks as a before validation callback' do
      expect(base_class).to receive(:before_validation).with(:nilify_blanks)

      # capture for class_eval scope
      described_class = self.described_class

      base_class.class_eval do
        include described_class
      end
    end
  end

  context 'nilify_blank' do
    it 'should support adding multiple attributes' do
      attributes = [:a, :b]

      base_class.nilify_blank(*attributes)

      attributes.each do |attribute|
        expect(base_class.nilify_blank_attribute_set).to include(attribute)
      end
    end

    it 'should not add duplicate attributes' do
      attribute = :a

      base_class.nilify_blank attribute
      base_class.nilify_blank attribute

      expect(base_class.nilify_blank_attribute_set.length).to eq(1)
    end
  end

  context '#nilify_blanks' do
    subject(:nilify_blanks) do
      base_instance.nilify_blanks
    end

    let(:base_instance) do
      base_class.new
    end

    let(:value) do
      'value'
    end

    before(:example) do
      base_class.class_eval do
        #
        # Attributes
        #

        # @!attribute [rw] blank
        #   @return [String, nil]
        attr_accessor :blank

        #
        # Callbacks
        #

        nilify_blank :blank
      end

      base_instance.blank = value
    end

    it 'should check if value responds to blank?' do
      expect(value).to receive(:respond_to?).with(:blank?)

      nilify_blanks
    end

    context 'with value responds to blank?' do
      it 'should call blank?' do
        expect(value).to receive(:blank?)

        nilify_blanks
      end

      context 'with blank' do
        let(:value) do
          ''
        end

        it 'should set attribute to nil' do
          nilify_blanks

          expect(base_instance.blank).to be_nil
        end
      end

      context 'without blank' do
        let(:value) do
          'value'
        end

        it 'should not change attribute' do
          expect {
            nilify_blanks
          }.to_not change(base_instance, :blank)
        end
      end
    end

    context 'without value responds to blank?' do
      let(:value) do
        double('Value')
      end

      before(:example) do
        allow(value).to receive(:respond_to?).with(:blank?).and_return(false)
      end

      it 'should not call blank?' do
        expect(value).not_to receive(:blank?)

        nilify_blanks
      end
    end
  end

  context 'nilify_blank_attribute_set' do
    subject(:nilify_blank_attribute_set) do
      base_class.nilify_blank_attribute_set
    end

    it 'should default to an empty Set' do
      expect(nilify_blank_attribute_set).to eq(Set.new)
    end
  end
end
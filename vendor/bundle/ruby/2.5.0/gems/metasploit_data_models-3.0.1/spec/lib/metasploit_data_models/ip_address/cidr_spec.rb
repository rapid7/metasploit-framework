RSpec.describe MetasploitDataModels::IPAddress::CIDR, type: :model do
  subject(:including_class_instance) {
    including_class.new(
        value: formatted_value
    )
  }

  #
  # lets
  #

  let(:expected_address) {
    double(
        '#address',
        valid?: true
    )
  }

  let(:expected_address_class) {
    double(
        '#address_class',
        new: expected_address,
        regexp: expected_address_class_regexp,
        segment_class: segment_class,
        segment_count: segment_count
    )
  }

  let(:expected_address_class_regexp) {
    /\d+\.\d+/
  }

  let(:formatted_value) {
    nil
  }

  let(:including_class) {
    expected_address_class = self.expected_address_class
    described_class = self.described_class

    Class.new(Metasploit::Model::Base) do
      include described_class

      #
      # CIDR
      #

      cidr address_class: expected_address_class
    end
  }

  let(:segment_bits) {
    4
  }

  let(:segment_class) {
    double(
        '#address_class segment_class',
        bits: segment_bits
    )
  }

  let(:segment_count) {
    2
  }

  #
  # Callbacks
  #

  before(:example) do
    stub_const('IncludingClass', including_class)
  end

  context 'CONSTANTS' do
    context 'SEPARATOR' do
      subject(:separator) {
        described_class::SEPARATOR
      }

      it { is_expected.to eq('/') }
    end
  end

  context 'validation errors on' do
    before(:example) do
      including_class_instance.valid?
    end

    context '#address' do
      subject(:address_errors) {
        including_class_instance.errors[:address]
      }

      context 'with #address' do
        let(:expected_address) {
          super().tap { |address|
            expect(address).to receive(:valid?).and_return(address_valid)
          }
        }

        let(:invalid_error) {
          I18n.translate!('errors.messages.invalid')
        }

        context 'with valid' do
          let(:address_valid) {
            true
          }

          it { is_expected.not_to include(invalid_error) }
        end

        context 'without valid' do
          let(:address_valid) {
            false
          }

          it { is_expected.to include(invalid_error) }
        end
      end

      context 'without #address' do
        let(:expected_address) {
          nil
        }

        let(:blank_error) {
          I18n.translate!('errors.messages.blank')
        }

        it { is_expected.to include(blank_error) }
      end
    end

    context '#prefix_length' do
      let(:maximum_prefix_length) {
        segment_count * segment_bits
      }

      it 'validates it is an integer between 0 and maximum_prefix_length' do
        expect(including_class_instance).to validate_numericality_of(:prefix_length).only_integer.is_greater_than_or_equal_to(0).is_less_than_or_equal_to(maximum_prefix_length)
      end
    end
  end

  context 'address_class' do
    subject(:address_class) do
      including_class.address_class
    end

    context 'with call to cidr' do
      it 'is value for :address_class key passed to cidr' do
        expect(address_class).to eq(expected_address_class)
      end
    end

    context 'without call to cidr' do
      let(:including_class) {
        described_class = self.described_class

        Class.new(Metasploit::Model::Base) do
          include described_class
        end
      }

      it { is_expected.to be_nil }
    end
  end

  context 'match_regexp' do
    subject(:match_regexp) {
      including_class.match_regexp
    }

    before(:example) do
      expect(including_class).to receive(:regexp).and_return(/regexp/)
    end

    it "is regexp pinned with '\\A' and '\\z'" do
      expect(match_regexp).to eq(/\A(?-mix:regexp)\z/)
    end
  end

  context 'maximum_prefix_length' do
    subject(:maximum_prefix_length) {
      including_class.maximum_prefix_length
    }

    it 'is the total number of bits across all segments' do
      expect(maximum_prefix_length).to eq(segment_count * segment_bits)
    end
  end

  context 'regexp' do
    subject(:regexp) {
      including_class.regexp
    }

    it 'includes address_class.regexp' do
      expect(regexp.to_s).to include(expected_address_class_regexp.to_s)
    end

    context 'Regexp#names' do
      subject(:names) {
        regexp.names
      }

      it { is_expected.to include 'address' }
      it { is_expected.to include 'prefix_length' }
    end
  end

  context '#address' do
    subject(:address) {
      including_class_instance.address
    }

    let(:expected_address_class) {
      Class.new(Metasploit::Model::Base) {
        attr_accessor :value
      }.tap { |address_class|
        outer_segment_class = self.segment_class

        address_class.define_singleton_method(:segment_class) do
          outer_segment_class
        end

        outer_segment_count = self.segment_count

        address_class.define_singleton_method(:segment_count) do
          outer_segment_count
        end
      }
    }

    context 'writer' do
      #
      # lets
      #

      let(:formatted_address) {
        '1.2'
      }

      it 'sets address_class #value' do
        including_class_instance

        expect(expected_address_class).to receive(:new).with(
                                              hash_including(
                                                  value: formatted_value
                                              )
                                          )

        including_class_instance.address = formatted_value
      end
    end
  end

  context '#prefix_length' do
    subject(:prefix_length) {
      including_class_instance.prefix_length
    }

    let(:formatted_address) {
      ''
    }

    let(:formatted_value) {
      "#{formatted_address}/#{formatted_prefix_length}"
    }

    context 'with integer' do
      let(:formatted_prefix_length) {
        expected_prefix_length.to_s
      }

      let(:expected_prefix_length) {
        7
      }

      it 'sets #prefix_length_before_type_cast to formatted prefix length' do
        expect(including_class_instance.prefix_length_before_type_cast).to eq(formatted_prefix_length)
      end

      it 'is set to Integer' do
        expect(prefix_length).to eq(expected_prefix_length)
      end
    end

    context 'without integer' do
      let(:formatted_prefix_length) {
        '255.255.255.0'
      }

      it 'sets #prefix_length_before_type_cast to formatted prefix length' do
        expect(including_class_instance.prefix_length_before_type_cast).to eq(formatted_prefix_length)
      end

      it 'is set to the formatted prefix length' do
        expect(prefix_length).to eq(formatted_prefix_length)
      end
    end
  end

  context '#value' do
    subject(:value) {
      including_class_instance.value
    }

    let(:formatted_address) {
      '1.2'
    }

    context "with '/'" do
      let(:formatted_value) {
        "#{formatted_address}/#{formatted_prefix_length}"
      }

      let(:formatted_prefix_length) {
        '7'
      }

      it "sets #address to formatted address before '/'" do
        expect(including_class_instance).to receive(:address=).with(formatted_address)

        including_class_instance.value = formatted_value
      end

      it "sets #prefix_length to formatted prefix length after '/'" do
        expect(including_class_instance).to receive(:prefix_length=).with(formatted_prefix_length)

        including_class_instance.value = formatted_value
      end
    end

    context "without '/'" do
      let(:formatted_value) {
        "#{formatted_address}"
      }


      it "sets #address to formatted address before '/'" do
        expect(including_class_instance).to receive(:address=).with(formatted_address)

        including_class_instance.value = formatted_value
      end

      it "sets #prefix_length to nil" do
        expect(including_class_instance).to receive(:prefix_length=).with(nil)

        including_class_instance.value = formatted_value
      end
    end
  end
end
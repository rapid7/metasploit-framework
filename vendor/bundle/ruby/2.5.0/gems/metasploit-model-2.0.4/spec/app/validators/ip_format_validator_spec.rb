RSpec.describe IpFormatValidator do
  subject(:ip_format_validator) do
    described_class.new(
        :attributes => attributes
    )
  end

  let(:attribute) do
    :address
  end

  let(:attributes) do
    [
        attribute
    ]
  end

  context '#validate_each' do
    subject(:validate_each) do
      ip_format_validator.validate_each(record, attribute, value)
    end

    let(:error) do
      'must be a valid IPv4 or IPv6 address'
    end

    let(:record) do
      record_class.new
    end

    let(:record_class) do
      # capture for Class.new scope
      attribute = self.attribute

      Class.new do
        include ActiveModel::Validations

        #
        # Validations
        #

        validates attribute,
                  :ip_format => true
      end
    end

    context 'with value' do
      context 'with IPv4 address' do
        let(:value) do
          '192.168.0.1'
        end

        it 'should not record any errors' do
          validate_each

          expect(record.errors).to be_empty
        end
      end

      context 'with IPv6 address' do
        let(:value) do
          '::1'
        end

        it 'should not record any errors' do
          validate_each

          expect(record.errors).to be_empty
        end
      end

      context 'with IPv4 range' do
        let(:value) do
          '127.0.0.1/8'
        end

        it 'should record error' do
          validate_each

          expect(record.errors[attribute]).to include("#{error} and not an IPv4 address range in CIDR or netmask notation")
        end
      end

      context 'with IPv6 range' do
        let(:value) do
          '3ffe:505:2::1/48'
        end

        it 'should record error' do
          validate_each

          expect(record.errors[attribute]).to include("#{error} and not an IPv6 address range in CIDR or netmask notation")
        end
      end

      context 'without IPv4 or IPv6 address' do
        let(:value) do
          'localhost'
        end

        it 'should record error' do
          validate_each

          expect(record.errors[attribute]).to include(error)
        end
      end

    end

    context 'without value' do
      let(:value) do
        nil
      end

      it 'should record error on attribute' do
        validate_each

        expect(record.errors[attribute]).to include(error)
      end
    end
  end
end
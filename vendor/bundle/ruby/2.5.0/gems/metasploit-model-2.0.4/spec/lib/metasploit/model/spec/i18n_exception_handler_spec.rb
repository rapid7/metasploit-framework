RSpec.describe Metasploit::Model::Spec::I18nExceptionHandler do
  subject(:i18n_exception_handler) do
    described_class.new
  end

  context '#call' do
    subject(:call) do
      i18n_exception_handler.call(exception, locale, key, options)
    end

    let(:exception) do
      I18n::MissingTranslation.new(locale, key, options)
    end

    let(:locale) do
      :en
    end

    let(:key) do
      :'missing.key'
    end

    let(:options) do
      {}
    end

    it 'should raise exception.to_exception' do
      converted_exception = exception.to_exception

      expect {
        call
      }.to raise_error(converted_exception.class) do |actual_exception|
        expect(actual_exception.class).to eq(converted_exception.class)
        expect(actual_exception.key).to eq(converted_exception.key)
        expect(actual_exception.locale).to eq(converted_exception.locale)
        expect(actual_exception.options).to eq(converted_exception.options)
      end
    end
  end
end
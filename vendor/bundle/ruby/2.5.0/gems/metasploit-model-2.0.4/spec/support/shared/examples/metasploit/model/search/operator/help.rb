RSpec.shared_examples_for 'Metasploit::Model::Search::Operator::Help' do
  context '#help' do
    subject(:help) do
      operator.help
    end

    let(:help_template) do
      "%{name} operator for searching %{model}"
    end

    let(:klass) do
      Class.new(Metasploit::Model::Base)
    end

    let(:model) do
      'Klass'
    end

    let(:name) do
      'operator_name'
    end

    before(:example) do
      # klass needs to be named or model_name will fail.
      stub_const('Klass', klass)
      # since missing translations raise exceptions, and there is no translation for klass, have to stub out.
      allow(klass.model_name).to receive(:human).and_return(model)

      backend = I18n.backend

      unless backend.initialized?
        backend.send(:init_translations)
      end

      translations_by_locale = I18n.backend.send(:translations)
      english_translations = translations_by_locale.fetch(:en)
      metasploit_translations = english_translations.fetch(:metasploit)
      @metasploit_model_translations = metasploit_translations.fetch(:model)

      expect(@metasploit_model_translations).not_to have_key(:ancestors)

      @metasploit_model_translations[:ancestors] = {
          klass.model_name.i18n_key => {
              search: {
                  operator: {
                      names: {
                          name.to_sym => {
                              help: help_template
                          }
                      }
                  }
              }
          }
      }
    end

    after(:example) do
      @metasploit_model_translations.delete(:ancestors)
    end

    it 'should use #klass #i18n_scope to lookup translations specific to the #klass or one of its ancestors' do
      expect(klass).to receive(:i18n_scope).and_call_original

      help
    end

    it 'should lookup ancestors of #klass to find translations specific to #klass or its ancestors' do
      expect(klass).to receive(:lookup_ancestors).and_call_original

      help
    end

    it 'should use #class #i18n_scope to lookup translations specific to the operator class or one of its ancestors' do
      expect(operator.class).to receive(:i18n_scope)

      help
    end

    it 'should lookup ancestors of the operator class to find translations specific to the operator class or one of its ancestors' do
      expect(operator.class).to receive(:lookup_ancestors).and_return([])

      help
    end

    it "should pass #klass translation key for operator with the given name as the primary translation key" do
      expect(I18n).to receive(:translate).with(
          :"#{klass.i18n_scope}.ancestors.#{klass.model_name.i18n_key}.search.operator.names.#{name}.help",
          anything
      )

      help
    end

    it 'should pass other translation keys as default option' do
      expect(I18n).to receive(:translate) do |_key, options|
        expect(options).to be_a Hash

        default = options[:default]

        expect(default).to be_an Array

        expect(
            default.all? { |key|
              key.is_a? Symbol
            }
        ).to eq(true)
      end

      help
    end

    it 'should pass #name of operator as name option' do
      expect(I18n).to receive(:translate).with(
          anything,
          hash_including(name: name)
      )

      help
    end

    it 'should pass the human model name of #klass as model option' do
      expect(I18n).to receive(:translate).with(
          anything,
          hash_including(model: klass.model_name.human)
      )

      help
    end

    it 'should be translated correctly' do
      expect(help).to eq(help_template % { model: model, name: name })
    end
  end
end
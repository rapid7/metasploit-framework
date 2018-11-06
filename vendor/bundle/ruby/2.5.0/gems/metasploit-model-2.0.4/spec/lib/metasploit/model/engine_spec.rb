RSpec.describe Metasploit::Model::Engine do
  context 'config' do
    subject(:config) do
      described_class.config
    end

    context 'generators' do
      subject(:generators) do
        config.generators
      end

      context 'options' do
        subject(:options) do
          generators.options
        end

        context 'factory_girl' do
          subject(:factory_girl) do
            options[:factory_girl]
          end

          context 'dir' do
            subject(:dir) {
              factory_girl[:dir]
            }

            it { is_expected.to eq('spec/factories') }
          end
        end

        context 'rails' do
          subject(:rails) do
            options[:rails]
          end

          context 'assets' do
            subject(:assets) {
              rails[:assets]
            }

            it { is_expected.to eq(false) }
          end

          context 'fixture_replacement' do
            subject(:fixture_replacement) {
              rails[:fixture_replacement]
            }

            it { is_expected.to eq(:factory_girl) }
          end

          context 'helper' do
            subject(:helper) {
              rails[:helper]
            }

            it { is_expected.to eq(false) }
          end

          context 'test_framework' do
            subject(:test_framework) {
              rails[:test_framework]
            }

            it { is_expected.to eq(:rspec) }
          end
        end

        context 'rspec' do
          subject(:rspec) do
            options[:rspec]
          end

          context 'fixture' do
            subject(:fixture) {
              rspec[:fixture]
            }

            it { is_expected.to eq(false) }
          end
        end
      end
    end
  end

  context 'initializers' do
    subject(:initializers) do
      # need to use Rails's initialized copy of Dummy::Application so that initializers have the correct context when
      # run
      Rails.application.initializers
    end

    context 'metasploit-model.prepend_factory_path' do
      subject(:initializer) do
        initializers.find { |initializer|
          initializer.name == 'metasploit-model.prepend_factory_path'
        }
      end

      it 'should run after factory_girl.set_factory_paths' do
        expect(initializer.after).to eq('factory_girl.set_factory_paths')
      end

      context 'running' do
        def run
          initializer.run
        end

        context 'with FactoryGirl defined' do
          it 'should prepend full path to spec/factories to FactoryGirl.definition_file_paths' do
            definition_file_path = Metasploit::Model::Engine.root.join('spec', 'factories')

            expect(FactoryGirl.definition_file_paths).to receive(:unshift).with(definition_file_path)

            run
          end
        end
      end
    end
  end
end
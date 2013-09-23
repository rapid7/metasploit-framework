require 'spec_helper'

describe Metasploit::Framework do
  let(:expected_root) do
    spec_lib_framework_pathname = Pathname.new(__FILE__).parent
    spec_lib_pathname = spec_lib_framework_pathname.parent
    spec_pathname = spec_lib_pathname.parent
    spec_pathname.parent
  end

  context 'autoload_paths' do
    subject(:autoload_paths) do
      described_class.autoload_paths
    end

    it 'should include app/models' do
      autoload_paths.should include(expected_root.join('app', 'models').to_path)
    end

    it 'should include app/validators' do
      autoload_paths.should include(expected_root.join('app', 'validators').to_path)
    end

    it 'should include lib' do
      autoload_paths.should include(expected_root.join('lib').to_path)
    end

    it 'should be in ActiveSupport::Dependencies.autoload_paths' do
      autoload_paths.each do |autoload_path|
        ActiveSupport::Dependencies.autoload_paths.should include(autoload_path)
      end
    end
  end

  context 'env' do
    subject(:env) do
      described_class.env
    end

    # Since the spec environment depends on env, need to ensure it is restored if an example fails so other examples
    # aren't messed up.
    around(:each) do |example|
      if described_class.instance_variable_defined? :@env
        # if defined before test, then restore value from before test at end of test.
        env_before = described_class.send(:remove_instance_variable, :@env)

        begin
          example.run
        ensure
          described_class.instance_variable_set :@env, env_before
        end
      else
        # if not defined before test, then make sure its not defined after test.
        begin
          example.run
        ensure
          if described_class.instance_variable_defined? :@env
            described_class.send(:remove_instance_variable, :@env)
          end
        end
      end
    end

    # Make sure ENV is restored too since its global
    around(:each) do |example|
      metasploit_framework_env_before = ENV.delete('METASPLOIT_FRAMEWORK_ENV')

      begin
        example.run
      ensure
        ENV['METASPLOIT_FRAMEWORK_ENV'] = metasploit_framework_env_before
      end
    end

    context 'with METASPLOIT_FRAMEWORK_ENV environment variable' do
      let(:metasploit_framework_env) do
        'metasploit_framework_env'
      end

      before(:each) do
        ENV['METASPLOIT_FRAMEWORK_ENV'] = metasploit_framework_env
      end

      it 'should use METASPLOIT_FRAMEWORK_ENV environment variable' do
        env.should == metasploit_framework_env
      end
    end

    context 'without METASPLOIT_FRAMEWORK_ENV environment variable' do
      before(:each) do
        ENV['METASPLOIT_FRAMEWORK_ENV'] = nil
      end

      it "should default to 'development' like Rails" do
        env.should == 'development'
      end
    end

    it { should be_a ActiveSupport::StringInquirer }
  end

  context 'locales' do
    subject('locales') do
      [
          expected_root.join('config', 'locales', 'en.yml').to_path
      ]
    end

    it 'should be included in I18n.load_path' do
      locales.each do |locale|
        I18n.load_path.should include(locale)
      end
    end
  end

  context 'root' do
    subject(:root) do
      described_class.root
    end

    it 'should be the project root' do
      root.should == expected_root
    end

    it { should be_a Pathname }
  end
end
# -*- coding:binary -*-

require 'spec_helper'

RSpec.shared_context 'datastore subjects', shared_context: :metadata do
  subject(:default_subject) do
    described_class.new
  end

  subject(:datastore_with_simple_options) do
    s = default_subject.copy
    options = Msf::OptionContainer.new(
      [
        Msf::OptString.new(
          'foo',
          [true, 'foo option', 'default_foo_value']
        ),
        Msf::OptString.new(
          'bar',
          [true, 'bar option', 'default_bar_value']
        ),
        Msf::OptString.new(
          'baz',
          [false, 'baz option']
        )
      ]
    )
    s.import_options(options)
    s
  end

  subject(:datastore_with_aliases) do
    s = default_subject.copy

    options = Msf::OptionContainer.new(
      [
        Msf::OptString.new(
          'NewOptionName',
          [true, 'An option with a new name. Aliases ensure the old and new names are synchronized', 'default_value'],
          aliases: ['OLD_OPTION_NAME']
        )
      ]
    )

    s.import_options(options)
    s
  end

  subject(:datastore_with_fallbacks) do
    s = default_subject.copy

    options = Msf::OptionContainer.new(
      [
        Msf::OptString.new(
          'SMBUser',
          [true, 'The SMB username'],
          fallbacks: ['username']
        ),

        Msf::OptString.new(
          'SMBDomain',
          [true, 'The SMB username', 'WORKGROUP'],
          fallbacks: ['domain']
        ),

        Msf::OptString.new(
          'USER_ATTR',
          [true, 'The ldap username'],
          fallbacks: ['username']
        ),
      ]
    )

    s.import_options(options)
    s
  end

  subject(:complex_datastore) do
    datastore_with_simple_options
      .merge(datastore_with_aliases)
      .merge(datastore_with_fallbacks)
  end

  subject(:complex_datastore_with_imported_defaults) do
    s = complex_datastore.copy
    s.import_defaults_from_hash(
      {
        'foo' => 'overridden_default_foo',
        'NewOptionName' => 'overridden_default_new_option_name'
      },
      imported_by: 'datastore_spec'
    )
    s
  end
end

RSpec.shared_examples_for 'a datastore with lookup support' do |opts = {}|
  it { is_expected.to respond_to :[] }
  it { is_expected.to respond_to :[]= }
  it { is_expected.to respond_to :unset }
  it { is_expected.to respond_to :delete }

  describe '#[]' do
    it 'should have default keyed values' do
      expect(subject['foo']).to eq 'foo_value'
      expect(subject['bar']).to eq 'bar_value'
    end

    it 'should have case-insensitive lookups' do
      # Sorted by gray code, just for fun
      expect(subject['foo']).to eq 'foo_value'
      expect(subject['Foo']).to eq 'foo_value'
      expect(subject['FOo']).to eq 'foo_value'
      expect(subject['fOo']).to eq 'foo_value'
      expect(subject['fOO']).to eq 'foo_value'
      expect(subject['FOO']).to eq 'foo_value'
      expect(subject['FoO']).to eq 'foo_value'
      expect(subject['foO']).to eq 'foo_value'
    end
  end

  describe '#length' do
    it 'should return a number' do
      expect(subject.length).to be > 0
    end
  end

  describe '#count' do
    it 'should return a number' do
      expect(subject.length).to be > 0
    end
  end

  context '#to_h' do
    it 'should return a Hash with correct values' do
      expected_to_h = opts.fetch(:expected_to_h) do
        { 'foo' => 'foo_value', 'bar' => 'bar_value' }
      end
      expect(subject.to_h).to eq(expected_to_h)
    end
  end
end

RSpec.shared_examples_for 'a datastore' do
  describe '#import_options' do
    let(:foo_option) do
      Msf::OptString.new(
        'foo',
        [true, 'foo option', 'default_foo_value']
      )
    end
    let(:bar_option) do
      Msf::OptString.new(
        'bar',
        [true, 'bar option', 'default_bar_value']
      )
    end
    subject do
      s = default_subject
      options = Msf::OptionContainer.new(
        [
          foo_option,
          bar_option
        ]
      )
      s.import_options(options)
      s
    end

    it 'should import the given options' do
      expected_options = {
        'foo' => foo_option,
        'bar' => bar_option
      }

      expect(subject.options).to eq(expected_options)
    end
  end

  describe '#import_options_from_hash' do
    subject do
      hash = { 'foo' => 'foo_value', 'bar' => 'bar_value' }
      s = default_subject
      s.import_options_from_hash(hash)
      s
    end
    it_behaves_like 'a datastore with lookup support'
  end

  describe '#import_options_from_s' do
    subject do
      str = 'foo=foo_value bar=bar_value'
      s = default_subject
      s.import_options_from_s(str)
      s
    end
    it_behaves_like 'a datastore with lookup support'

    context "parsing corner cases" do
      it "should parse comma separated strings" do
        str = "foo=bar,fizz=buzz"
        subject.import_options_from_s(str)

        expect(subject).to have_key("foo")
        expect(subject["foo"]).to eql("bar")
        expect(subject).to have_key("fizz")
        expect(subject["fizz"]).to eql("buzz")
      end

      it "should parse options with nested equals" do
        str = "COMMAND=date --date=2023-01-01 --iso-8601=ns,SESSION=1"
        subject.import_options_from_s(str)

        expect(subject).to have_key("COMMAND")
        expect(subject["COMMAND"]).to eql("date --date=2023-01-01 --iso-8601=ns")
        expect(subject).to have_key("SESSION")
        expect(subject["SESSION"]).to eql("1")
      end
    end
  end

  describe '#from_file' do
    subject do
      ini_instance = double group?: true,
                            :[] => {
                              'foo' => 'foo_value',
                              'bar' => 'bar_value'
                            }
      ini_class = double from_file: ini_instance

      stub_const('Rex::Parser::Ini', ini_class)

      s = default_subject
      s.from_file('path')
      s
    end

    it_behaves_like 'a datastore with lookup support'
  end

  describe '#user_defined' do
    subject do
      complex_datastore
    end

    context 'when no options have been set' do
      it 'should return an empty hash' do
        expect(subject.user_defined).to eq({})
      end
    end

    context 'when a value has been unset' do
      before(:each) do
        subject.unset('foo')
      end

      it 'should should not include the unset values' do
        expect(subject.user_defined).to eq({})
      end
    end

    context 'when values have been explicitly set' do
      before(:each) do
        subject['foo'] = 'foo_value'
        subject['custom_key'] = 'custom_key_value'
        subject['OLD_OPTION_NAME'] = 'old_option_name_value'
        subject['SMBUser'] = 'smbuser_user'
      end

      it 'should return the set values' do
        expected_values = {
          'NewOptionName' => 'old_option_name_value',
          'custom_key' => 'custom_key_value',
          'foo' => 'foo_value',
          'SMBUser' => 'smbuser_user'
        }
        expect(subject.user_defined).to eq(expected_values)
      end
    end

    context 'when a fallback has been set' do
      before(:each) do
        subject.merge!(
          {
            'username' => 'username'
          }
        )
      end

      it 'should not return SMBUser/USER_ATTR etc' do
        expected_values = {
          'username' => 'username'
        }
        expect(subject.user_defined).to eq(expected_values)
      end
    end

    context 'when values have been merged with a hash' do
      before(:each) do
        subject.merge!(
          {
            'NewOptionName' => 'old_option_name_value',
            'custom_key' => 'custom_key_value',
            'FOO' => 'foo_value'
          }
        )
      end

      it 'should return the set values' do
        expected_values = {
          'NewOptionName' => 'old_option_name_value',
          'custom_key' => 'custom_key_value',
          'foo' => 'foo_value'
        }
        expect(subject.user_defined).to eq(expected_values)
      end
    end

    context 'when values have been merged with a datastore' do
      before(:each) do
        other_datastore = subject.copy
        subject.unset('foo')
        subject['bar'] = 'bar_value'
        subject['foo_bar'] = 'foo_bar_value'

        options = Msf::OptionContainer.new(
          Msf::Opt.stager_retry_options + Msf::Opt.http_proxy_options
        )

        other_datastore.import_options(options)
        other_datastore['BAR'] = 'new_bar_value'
        other_datastore['HttpProxyPass'] = 'http_proxy_pass_value'
        other_datastore['HttpProxyType'] = 'SOCKS'
        other_datastore.unset('FOO_BAR')
        other_datastore.import_defaults_from_hash({ 'PAYLOAD' => 'merged_default' }, imported_by: 'data_store_spec')

        subject.merge!(other_datastore)
      end

      it 'should return the set values' do
        expected_values = {
          'HttpProxyPass' => 'http_proxy_pass_value',
          'HttpProxyType' => 'SOCKS',
          'foo_bar' => 'foo_bar_value',
          'bar' => 'new_bar_value'
        }
        expect(subject.user_defined).to eq(expected_values)
      end

      it 'should still have defaults present' do
        expect(subject['payload']).to eq 'merged_default'
      end
    end
  end

  describe '#[]' do
    context 'when the datastore has no options registered' do
      subject do
        default_subject
      end

      it 'should reset the specified key' do
        expect(subject['foo']).to eq nil
        expect(subject['bar']).to eq nil
      end

      it 'should return imported defaults' do
        subject.import_defaults_from_hash({ 'PAYLOAD' => 'linux/armle/meterpreter_reverse_tcp' }, imported_by: 'data_store_spec')

        expect(subject.default?('payload')).to be true
        expect(subject.default?('PAYLOAD')).to be true
        expect(subject['PAYLOAD']).to eq 'linux/armle/meterpreter_reverse_tcp'
        expect(subject['payload']).to eq 'linux/armle/meterpreter_reverse_tcp'
      end
    end

    context 'when the datastore has aliases' do
      subject do
        datastore_with_aliases
      end

      it 'should have default keyed values' do
        expect(subject['NewOptionName']).to eq('default_value')
        expect(subject['OLD_OPTION_NAME']).to eq('default_value')
      end

      it 'should have case-insensitive lookups' do
        expect(subject['NEWOPTIONNAME']).to eq('default_value')
        expect(subject['Old_Option_Name']).to eq('default_value')
      end
    end

    context 'when the datastore has fallbacks' do
      subject do
        datastore_with_fallbacks
      end

      it 'should have default keyed values' do
        expect(subject['SMBUser']).to be(nil)
        expect(subject['SMBDomain']).to eq('WORKGROUP')
        expect(subject['USER_ATTR']).to be(nil)
        expect(subject['username']).to be(nil)
      end
    end
  end

  describe '#merge!' do
    context 'when merging with a hash' do
      subject do
        s = default_subject.copy
        options = Msf::OptionContainer.new(
          [
            Msf::OptFloat.new(
              'FloatValue',
              [false, 'A FloatValue', 3.5]
            )
          ]
        )
        s.import_options(options)
        s
      end

      # Note: This aligns the first implementation of the DataStore class.
      # In certain scenarios it does not seem like desired behavior.
      it 'does not perform option validation' do
        subject.merge!({ 'FloatValue' => 'invalid_value' })

        expect(subject['FloatValue']).to eq('invalid_value')
      end
    end
  end

  describe '#[]=' do
    context 'when the datastore has aliases' do
      subject do
        datastore_with_aliases
      end

      [
        nil,
        false,
        '',
        'new_value'
      ].each do |value|
        context "when the value is #{value.inspect}" do
          it 'should allow setting datastore values with the new option name' do
            subject['NewOptionName'] = value

            expect(subject['NewOptionName']).to eq(value)
            expect(subject['OLD_OPTION_NAME']).to eq(value)
          end

          it 'should allow setting datastore values with the old option name' do
            subject['OLD_OPTION_NAME'] = value

            expect(subject['NewOptionName']).to eq(value)
            expect(subject['OLD_OPTION_NAME']).to eq(value)
          end
        end
      end
    end

    context 'when the datastore has fallbacks' do
      subject do
        datastore_with_fallbacks
      end

      it 'should allow setting a key with fallbacks' do
        subject['SMBUser'] = 'username'
        expect(subject['SMBUser']).to eq('username')
        expect(subject['USER_ATTR']).to be(nil)
        expect(subject['username']).to be(nil)
      end

      it 'should allow setting a generic key' do
        subject['username'] = 'username'
        expect(subject['SMBUser']).to eq('username')
        expect(subject['USER_ATTR']).to eq('username')
        expect(subject['username']).to eq('username')
      end

      it 'should allow setting multiple keys with fallbacks' do
        subject['username'] = 'username_generic'
        subject['user_attr'] = 'username_attr'
        subject['smbuser'] = 'username_smb'
        expect(subject['SMBUser']).to eq('username_smb')
        expect(subject['USER_ATTR']).to eq('username_attr')
        expect(subject['username']).to eq('username_generic')
      end

      it 'should use the fallback in preference of the option default value' do
        subject['domain'] = 'example.local'
        expect(subject['SMBDomain']).to eq('example.local')
      end
    end
  end

  describe '#import_defaults_from_hash' do
    subject do
      complex_datastore.import_defaults_from_hash(
        {
          'foo' => 'overridden_default_foo',
          'NewOptionName' => 'overridden_default_new_option_name'
          # TODO: Add alias/old_option_name test as well
          # 'old_option_name' => 'overridden_default_old_option_name'
        },
        imported_by: 'self'
      )

      complex_datastore
    end

    it 'should have default keyed values' do
      expect(subject['foo']).to eq 'overridden_default_foo'
      expect(subject['bar']).to eq 'default_bar_value'
      expect(subject['NewOptionName']).to eq('overridden_default_new_option_name')
      expect(subject['OLD_OPTION_NAME']).to eq('overridden_default_new_option_name')
    end
  end

  describe '#unset' do
    context 'when the datastore has no options registered' do
      subject do
        default_subject
      end

      it 'should reset the value when it has been user defined' do
        subject['foo'] = 'new_value'

        expect(subject.unset('foo')).to eq 'new_value'
        expect(subject.unset('foo')).to eq nil
      end

      it 'should not change the value if not previously set' do
        expect(subject.unset('foo')).to eq nil
        expect(subject.unset('foo')).to eq nil
      end
    end

    context 'when the datastore has simple options' do
      subject do
        datastore_with_simple_options
      end

      it 'should reset the value when it has been user defined' do
        subject['foo'] = 'new_value'

        expect(subject.unset('foo')).to eq 'new_value'
        expect(subject.unset('foo')).to eq 'default_foo_value'
      end

      it 'should not change the value if not previously set' do
        expect(subject.unset('foo')).to eq 'default_foo_value'
        expect(subject.unset('foo')).to eq 'default_foo_value'
      end
    end

    context 'when the datastore has aliases' do
      subject do
        datastore_with_aliases
      end

      # Ensure that both the new name and old name can be used interchangeably
      [
        { set_key: 'NewOptionName', delete_key: 'NewOptionName' },
        { set_key: 'OLD_OPTION_NAME', delete_key: 'OLD_OPTION_NAME' },
        { set_key: 'NewOptionName', delete_key: 'OLD_OPTION_NAME' },
        { set_key: 'OLD_OPTION_NAME', delete_key: 'NewOptionName' },
      ].each do |test|
        context "when using #{test[:delete_key].inspect} to set the value and deleting with #{test[:delete_key].inspect}" do
          it 'should reset the value when it has been user defined' do
            subject[test[:set_key]] = 'new_value'

            expect(subject.unset(test[:delete_key])).to eq 'new_value'
            expect(subject.unset(test[:delete_key])).to eq 'default_value'
          end

          it 'should not change the value if not previously set' do
            expect(subject.unset(test[:delete_key])).to eq 'default_value'
            expect(subject.unset(test[:delete_key])).to eq 'default_value'
          end
        end
      end
    end

    context 'when the datastore has fallbacks' do
      subject do
        datastore_with_fallbacks
      end

      context 'when using the option name' do
        it 'should reset the value when it has been user defined' do
          subject['SMBDomain'] = 'new_value'

          expect(subject.unset('SMBDomain')).to eq 'new_value'
          expect(subject.unset('SMBDomain')).to eq 'WORKGROUP'
        end

        it 'should not change the value if not previously set' do
          expect(subject.unset('SMBDomain')).to eq 'WORKGROUP'
          expect(subject.unset('SMBDomain')).to eq 'WORKGROUP'
        end
      end

      context 'when using the fallback option name' do
        it 'should delete the value when it has been user defined' do
          subject['domain'] = 'new_value'

          # Explicitly unsetting SMBDomain shouldn't unset the domain
          expect(subject['SMBDomain']).to eq 'new_value'
          expect(subject.unset('SMBDomain')).to eq 'new_value'
          expect(subject.unset('SMBDomain')).to eq 'new_value'

          expect(subject['domain']).to eq 'new_value'
          expect(subject.unset('domain')).to eq 'new_value'
          expect(subject.unset('domain')).to eq nil
        end

        it 'should delete the value when it has not been user defined' do
          expect(subject.unset('domain')).to eq nil
          expect(subject.unset('SMBDomain')).to eq 'WORKGROUP'
          expect(subject['domain']).to eq nil
        end
      end
    end

    context 'when the datastore has imported defaults' do
      subject do
        complex_datastore_with_imported_defaults
      end

      it 'should reset the specified key' do
        subject['foo'] = 'new_value'
        subject.unset('foo')

        expect(subject['foo']).to eq 'overridden_default_foo'
      end
    end
  end

  context '#to_h' do
    context 'when the datastore has no options registered' do
      subject do
        default_subject
      end

      it 'should return a Hash with correct values' do
        expected_to_h = {
        }
        expect(subject.to_h).to eq(expected_to_h)
      end
    end

    context 'when the datastore has aliases' do
      subject do
        datastore_with_aliases
      end

      it 'should return a Hash with correct values' do
        expected_to_h = {
          'NewOptionName' => 'default_value'
        }
        expect(subject.to_h).to eq(expected_to_h)
      end
    end

    context 'when the datastore has fallbacks' do
      subject do
        datastore_with_fallbacks
      end

      it 'should return a Hash with correct values' do
        expected_to_h = {
          'SMBDomain' => 'WORKGROUP',
          'SMBUser' => '',
          'USER_ATTR' => ''
        }
        expect(subject.to_h).to eq(expected_to_h)
      end
    end

    context 'when the datastore has imported defaults' do
      subject do
        complex_datastore_with_imported_defaults
      end

      it 'should return a Hash with correct values' do
        expected_to_h = {
          'NewOptionName' => 'overridden_default_new_option_name',
          'SMBDomain' => 'WORKGROUP',
          'SMBUser' => '',
          'USER_ATTR' => '',
          'foo' => 'overridden_default_foo',
          'bar' => 'default_bar_value',
          'baz' => ''
        }
        expect(subject.to_h).to eq(expected_to_h)
      end
    end
  end
end

RSpec.describe Msf::DataStoreWithFallbacks do
  include_context 'datastore subjects'

  subject(:default_subject) do
    described_class.new
  end

  subject { default_subject }

  it_behaves_like 'a datastore'
end

RSpec.describe Msf::ModuleDataStoreWithFallbacks do
  include_context 'datastore subjects'

  let(:framework_datastore) do
    Msf::DataStoreWithFallbacks.new
  end
  let(:mod) do
    framework = instance_double(Msf::Framework, datastore: framework_datastore)
    instance_double(
      Msf::Exploit,
      framework: framework
    )
  end
  subject(:default_subject) do
    described_class.new mod
  end
  subject { default_subject }

  # @param [DataStoreSearchResult] search_result
  # @return [Symbol] a human readable result for where the search result was found or not found
  def human_readable_result_for(search_result)
    "#{search_result.instance_variable_get(:@namespace)}__#{search_result.instance_variable_get(:@result)}".to_sym
  end

  context 'when the framework datastore is empty' do
    it_behaves_like 'a datastore'
  end

  context 'when the global framework datastore has values' do
    describe '#default?' do
      context 'when the datastore has no options registered' do
        subject do
          default_subject
        end

        it 'should return true when the value is not set' do
          expect(subject.default?('foo')).to be true
        end

        it 'should return false if the value is set' do
          subject['foo'] = 'bar'

          expect(subject.default?('foo')).to be false
        end

        it 'should return true if the value has been unset' do
          expect(subject.default?('foo')).to be true
        end

        it 'should return imported defaults' do
          subject.import_defaults_from_hash({ 'PAYLOAD' => 'linux/armle/meterpreter_reverse_tcp' }, imported_by: 'data_store_spec')

          expect(subject.default?('payload')).to be true
          expect(subject.default?('PAYLOAD')).to be true
          expect(subject['PAYLOAD']).to eq 'linux/armle/meterpreter_reverse_tcp'
          expect(subject['payload']).to eq 'linux/armle/meterpreter_reverse_tcp'
        end
      end

      context 'when the datastore has aliases' do
        subject do
          datastore_with_aliases
        end

        # Ensure that both the new name and old name can be used interchangeably
        [
          { set_key: 'NewOptionName', read_key: 'NewOptionName' },
          { set_key: 'OLD_OPTION_NAME', read_key: 'OLD_OPTION_NAME' },
          { set_key: 'NewOptionName', read_key: 'OLD_OPTION_NAME' },
          { set_key: 'OLD_OPTION_NAME', read_key: 'NewOptionName' },
        ].each do |test|
          context "when using #{test[:set_key].inspect} to set the value and reading with #{test[:read_key].inspect}" do
            it 'should return true when the value is not set' do
              expect(subject.default?(test[:read_key])).to be true
            end

            it 'should return false if the value is set' do
              subject[test[:set_key]] = 'bar'

              expect(subject.default?(test[:read_key])).to be false
            end

            it 'should return true if the value has been unset' do
              subject.unset(test[:set_key])

              expect(subject.default?(test[:read_key])).to be true
            end
          end
        end
      end

      context 'when the datastore has fallbacks' do
        subject do
          datastore_with_fallbacks
        end

        it 'should return true when the value is not set' do
          expect(subject.default?('SMBDomain')).to be true
        end

        it 'should return false if the value is set' do
          subject['SMBDomain'] = 'bar'

          expect(subject.default?('SMBDomain')).to be false
        end

        it 'should return true if the value has been unset' do
          subject.unset('SMBDomain')

          expect(subject.default?('SMBDomain')).to be true
        end

        it 'should return false if the fallback value has been set' do
          subject['domain'] = 'foo'

          expect(subject.default?('SMBDomain')).to be false
        end

        it 'should return true if the fallback value has been unset' do
          subject['domain'] = 'foo'
          subject.unset('domain')

          expect(subject.default?('SMBDomain')).to be true
        end
      end
    end

    describe '#[]' do
      context 'when the datastore has no options registered' do
        subject do
          default_subject
        end

        it 'should return nil by default' do
          expect(subject['foo']).to eq nil
          expect(subject['bar']).to eq nil
        end

        context 'when the key has been set in the framework datastore' do
          it 'should fall back to the framework datastore' do
            framework_datastore['foo'] = 'global_foo_value'

            expect(subject['foo']).to eq 'global_foo_value'
            expect(subject['bar']).to eq nil
          end
        end
      end

      context 'when the datastore has aliases' do
        subject do
          datastore_with_aliases
        end

        it 'should have default keyed values' do
          expect(subject['NewOptionName']).to eq('default_value')
          expect(subject['OLD_OPTION_NAME']).to eq('default_value')
        end

        it 'should have case-insensitive lookups' do
          expect(subject['NEWOPTIONNAME']).to eq('default_value')
          expect(subject['Old_Option_Name']).to eq('default_value')
        end

        context 'when the key has been set in the framework datastore' do
          # Ensure that both the new name and old name can be used interchangeably
          [
            { set_key: 'NewOptionName', read_key: 'NewOptionName' },
            { set_key: 'OLD_OPTION_NAME', read_key: 'OLD_OPTION_NAME' },
            # Not supported/implemented - the global datastore does not have aliases registered
            # { set_key: 'NewOptionName', read_key: 'OLD_OPTION_NAME' },
            # { set_key: 'OLD_OPTION_NAME', read_key: 'NewOptionName' },
          ].each do |test|
            context "when using #{test[:set_key].inspect} to set the value and reading with #{test[:read_key].inspect}" do
              it 'should fall back to the framework datastore if it is set' do
                framework_datastore[test[:set_key]] = 'global_foo_value'

                expect(subject[test[:read_key]]).to eq 'global_foo_value'
              end

              it 'should fallback to default value if the parent datastore is unset' do
                framework_datastore.unset(test[:set_key])

                expect(subject[test[:read_key]]).to eq 'default_value'
              end
            end
          end
        end
      end

      context 'when the datastore has fallbacks' do
        subject do
          datastore_with_fallbacks
        end

        it 'should allow setting a key with fallbacks' do
          subject['SMBUser'] = 'username'
          expect(subject['SMBUser']).to eq('username')
          expect(subject['USER_ATTR']).to be(nil)
          expect(subject['username']).to be(nil)
        end

        it 'should allow setting a generic key' do
          subject['username'] = 'username'
          expect(subject['SMBUser']).to eq('username')
          expect(subject['USER_ATTR']).to eq('username')
          expect(subject['username']).to eq('username')
        end

        it 'should allow setting multiple keys with fallbacks' do
          subject['username'] = 'username_generic'
          subject['user_attr'] = 'username_attr'
          subject['smbuser'] = 'username_smb'
          expect(subject['SMBUser']).to eq('username_smb')
          expect(subject['USER_ATTR']).to eq('username_attr')
          expect(subject['username']).to eq('username_generic')
        end

        it 'should use the fallback in preference of the option default value' do
          subject['domain'] = 'example.local'
          expect(subject['SMBDomain']).to eq('example.local')
        end

        context 'when the key has been set in the framework datastore' do
          it 'should use the framework datastore if it is set' do
            framework_datastore['SMBUser'] = 'global_username_value'
            framework_datastore['SMBDomain'] = 'global_domain_value'

            expect(subject['SMBUser']).to eq 'global_username_value'
            expect(subject['USER_ATTR']).to eq nil
            expect(subject['SMBDomain']).to eq 'global_domain_value'
          end

          it 'should use the framework fallback datastore value if it is set' do
            framework_datastore['username'] = 'global_username_value'
            framework_datastore['domain'] = 'global_domain_value'

            expect(subject['SMBUser']).to eq 'global_username_value'
            expect(subject['USER_ATTR']).to eq 'global_username_value'
            expect(subject['SMBDomain']).to eq 'global_domain_value'
          end

          it 'should fallback to option default value if the parent datastore is unset' do
            framework_datastore.unset('SMBUser')
            framework_datastore.unset('SMBDomain')

            # expect(subject['SMBUser']).to eq nil
            # expect(subject['USER_ATTR']).to eq nil
            expect(subject['SMBDomain']).to eq 'WORKGROUP'
          end
        end
      end
    end

    describe '#[]=' do
      context 'when the datastore has aliases' do
        subject do
          datastore_with_aliases
        end

        [
          nil,
          false,
          '',
          'new_value'
        ].each do |value|
          context "when the value is #{value.inspect}" do
            it 'should allow setting datastore values with the new option name' do
              subject['NewOptionName'] = value

              expect(subject['NewOptionName']).to eq(value)
              expect(subject['OLD_OPTION_NAME']).to eq(value)
            end

            it 'should allow setting datastore values with the old option name' do
              subject['OLD_OPTION_NAME'] = value

              expect(subject['NewOptionName']).to eq(value)
              expect(subject['OLD_OPTION_NAME']).to eq(value)
            end
          end
        end
      end

      context 'when the datastore has fallbacks' do
        subject do
          datastore_with_fallbacks
        end

        it 'should allow setting a key with fallbacks' do
          subject['SMBUser'] = 'username'
          expect(subject['SMBUser']).to eq('username')
          expect(subject['USER_ATTR']).to be(nil)
          expect(subject['username']).to be(nil)
        end

        it 'should allow setting a generic key' do
          subject['username'] = 'username'
          expect(subject['SMBUser']).to eq('username')
          expect(subject['USER_ATTR']).to eq('username')
          expect(subject['username']).to eq('username')
        end

        it 'should allow setting multiple keys with fallbacks' do
          subject['username'] = 'username_generic'
          subject['user_attr'] = 'username_attr'
          subject['smbuser'] = 'username_smb'
          expect(subject['SMBUser']).to eq('username_smb')
          expect(subject['USER_ATTR']).to eq('username_attr')
          expect(subject['username']).to eq('username_generic')
        end

        it 'should use the fallback in preference of the option default value' do
          subject['domain'] = 'example.local'
          expect(subject['SMBDomain']).to eq('example.local')
        end
      end
    end
  end

  describe 'testing all the things' do
    context 'when the datastore has simple options' do
      subject do
        datastore_with_simple_options
      end

      [
        { option_default_value: nil, set_key: 'foo', set_value: nil },
        { option_default_value: '', set_key: 'foo', set_value: nil },
        { option_default_value: 'default_value', set_key: 'foo', set_value: nil },

        { option_default_value: nil, set_key: 'foo', set_value: '' },
        { option_default_value: '', set_key: 'foo', set_value: '' },
        { option_default_value: 'default_value', set_key: 'foo', set_value: '' },

        { option_default_value: nil, set_key: 'foo', set_value: 'set_value' },
        { option_default_value: '', set_key: 'foo', set_value: 'set_value' },
        { option_default_value: 'default_value', set_key: 'foo', set_value: 'set_value' },
      ].each do |test|
        context "when the option default value is #{test[:default_value]}" do
          option_default_value = test[:option_default_value]
          set_key = test[:set_key]
          set_value = test[:set_value]
          read_key = test[:set_key] || test[:read_key]

          before(:each) do
            subject.options['foo'].send(:default=, option_default_value)
          end

          # Test permutations, ints used for readability
          [
            # nothing changed on module
            { mod_set: 0, mod_unset: 0, framework_set: 0, framework_unset: 0, expected: { value: option_default_value, reason: :module_data_store__option_default, is_default: true } },
            { mod_set: 0, mod_unset: 0, framework_set: 0, framework_unset: 1, expected: { value: option_default_value, reason: :module_data_store__option_default, is_default: true } },
            { mod_set: 0, mod_unset: 0, framework_set: 1, framework_unset: 0, expected: { value: set_value, reason: :global_data_store__user_defined, is_default: false } },

            # module datastore unset
            { mod_set: 0, mod_unset: 1, framework_set: 0, framework_unset: 0, expected: { value: option_default_value, reason: :module_data_store__option_default, is_default: true } },
            { mod_set: 0, mod_unset: 1, framework_set: 0, framework_unset: 1, expected: { value: option_default_value, reason: :module_data_store__option_default, is_default: true } },
            { mod_set: 0, mod_unset: 1, framework_set: 1, framework_unset: 0, expected: { value: set_value, reason: :global_data_store__user_defined, is_default: false } },

            # module datastore set
            { mod_set: 1, mod_unset: 0, framework_set: 0, framework_unset: 0, expected: { value: set_value, reason: :module_data_store__user_defined, is_default: false } },
            { mod_set: 1, mod_unset: 0, framework_set: 0, framework_unset: 1, expected: { value: set_value, reason: :module_data_store__user_defined, is_default: false } },
            { mod_set: 1, mod_unset: 0, framework_set: 1, framework_unset: 0, expected: { value: set_value, reason: :module_data_store__user_defined, is_default: false } },
          ].each do |opts|
            context "when #{opts.inspect}" do
              it 'returns the expected value' do
                subject[set_key] = set_value if opts[:mod_set] == 1
                subject.unset(set_key) if opts[:mod_unset] == 1

                framework_datastore[set_key] = set_value if opts[:framework_set] == 1
                framework_datastore.unset(set_key) if opts[:framework_unset] == 1

                # Assertions
                expected = opts[:expected]
                search_result = subject.search_for(read_key)
                expect(search_result.value).to eq expected[:value]
                expect(human_readable_result_for(search_result)).to eq expected[:reason]
                expect(subject[read_key]).to eq expected[:value]
                expect(search_result.default?).to eq(expected[:is_default])
              end
            end
          end
        end
      end
    end

    context 'when the datastore has aliases options' do
      subject do
        datastore_with_aliases
      end

      # Ensure that both the new name and old name can be used interchangeably
      [
        { set_key: 'NewOptionName', read_key: 'NewOptionName' },
        { set_key: 'OLD_OPTION_NAME', read_key: 'OLD_OPTION_NAME' },
        { set_key: 'NewOptionName', read_key: 'OLD_OPTION_NAME' },
        { set_key: 'OLD_OPTION_NAME', read_key: 'NewOptionName' },
      ].each do |keys|
        set_key = keys[:set_key]
        read_key = keys[:read_key]

        context "when using #{keys[:set_key].inspect} to set the value and reading with #{keys[:read_key].inspect}" do
          [
            { option_default_value: nil, set_key: set_key, set_value: nil, read_key: read_key },
            { option_default_value: '', set_key: set_key, set_value: nil, read_key: read_key },
            { option_default_value: 'default_value', set_key: set_key, set_value: nil, read_key: read_key },

            { option_default_value: nil, set_key: set_key, set_value: '', read_key: read_key },
            { option_default_value: '', set_key: set_key, set_value: '', read_key: read_key },
            { option_default_value: 'default_value', set_key: set_key, set_value: '', read_key: read_key },

            { option_default_value: nil, set_key: set_key, set_value: 'set_value', read_key: read_key },
            { option_default_value: '', set_key: set_key, set_value: 'set_value', read_key: read_key },
            { option_default_value: 'default_value', set_key: set_key, set_value: 'set_value', read_key: read_key },
          ].each do |test|
            context "when the default value is #{test[:default_value]}" do
              option_default_value = test[:option_default_value]
              set_key = test[:set_key]
              set_value = test[:set_value]
              read_key = test[:set_key] || test[:read_key]

              before(:each) do
                subject.options['NewOptionName'].send(:default=, option_default_value)
              end

              # Test permutations, ints used for readability
              [
                # nothing changed on module
                { mod_set: 0, mod_unset: 0, framework_set: 0, framework_unset: 0, expected: { value: option_default_value, reason: :module_data_store__option_default, is_default: true } },
                { mod_set: 0, mod_unset: 0, framework_set: 0, framework_unset: 1, expected: { value: option_default_value, reason: :module_data_store__option_default, is_default: true } },
                { mod_set: 0, mod_unset: 0, framework_set: 1, framework_unset: 0, expected: { value: set_value, reason: :global_data_store__user_defined, is_default: false } },

                # module datastore unset
                { mod_set: 0, mod_unset: 1, framework_set: 0, framework_unset: 0, expected: { value: option_default_value, reason: :module_data_store__option_default, is_default: true } },
                { mod_set: 0, mod_unset: 1, framework_set: 0, framework_unset: 1, expected: { value: option_default_value, reason: :module_data_store__option_default, is_default: true } },
                { mod_set: 0, mod_unset: 1, framework_set: 1, framework_unset: 0, expected: { value: set_value, reason: :global_data_store__user_defined, is_default: false } },

                # module datastore set
                { mod_set: 1, mod_unset: 0, framework_set: 0, framework_unset: 0, expected: { value: set_value, reason: :module_data_store__user_defined, is_default: false } },
                { mod_set: 1, mod_unset: 0, framework_set: 0, framework_unset: 1, expected: { value: set_value, reason: :module_data_store__user_defined, is_default: false } },
                { mod_set: 1, mod_unset: 0, framework_set: 1, framework_unset: 0, expected: { value: set_value, reason: :module_data_store__user_defined, is_default: false } },
              ].each do |opts|
                context "when #{opts.inspect}" do
                  it 'returns the expected value' do
                    subject[set_key] = set_value if opts[:mod_set] == 1
                    subject.unset(set_key) if opts[:mod_unset] == 1

                    framework_datastore[set_key] = set_value if opts[:framework_set] == 1
                    framework_datastore.unset(set_key) if opts[:framework_unset] == 1

                    # Assertions
                    expected = opts[:expected]
                    search_result = subject.search_for(read_key)
                    expect(search_result.value).to eq expected[:value]
                    expect(human_readable_result_for(search_result)).to eq expected[:reason]
                    expect(subject[read_key]).to eq expected[:value]
                    expect(search_result.default?).to eq(expected[:is_default])
                  end
                end
              end
            end
          end
        end
      end
    end

    context 'when the datastore has defaults imported' do
      subject do
        complex_datastore_with_imported_defaults
      end

      [
        { option_default_value: nil, set_key: 'foo', set_value: nil },
        { option_default_value: '', set_key: 'foo', set_value: nil },
        { option_default_value: 'default_value', set_key: 'foo', set_value: nil },

        { option_default_value: nil, set_key: 'foo', set_value: '' },
        { option_default_value: '', set_key: 'foo', set_value: '' },
        { option_default_value: 'default_value', set_key: 'foo', set_value: '' },

        { option_default_value: nil, set_key: 'foo', set_value: 'set_value' },
        { option_default_value: '', set_key: 'foo', set_value: 'set_value' },
        { option_default_value: 'default_value', set_key: 'foo', set_value: 'set_value' },
      ].each do |test|
        context "when the option default value is #{test[:option_default_value]}" do
          option_default_value = test[:option_default_value]
          import_default_value = 'test'
          set_key = test[:set_key]
          set_value = test[:set_value]
          read_key = test[:set_key] || test[:read_key]

          before(:each) do
            subject.options[set_key].send(:default=, option_default_value)
            subject.import_defaults_from_hash({ set_key => import_default_value }, imported_by: 'data_store_spec')
          end

          # Test permutations, ints used for readability
          [
            # nothing changed on module
            { mod_set: 0, mod_unset: 0, framework_set: 0, framework_unset: 0, expected: { value: import_default_value, reason: :module_data_store__imported_default, is_default: true } },
            { mod_set: 0, mod_unset: 0, framework_set: 0, framework_unset: 1, expected: { value: import_default_value, reason: :module_data_store__imported_default, is_default: true } },
            { mod_set: 0, mod_unset: 0, framework_set: 1, framework_unset: 0, expected: { value: set_value, reason: :global_data_store__user_defined, is_default: false } },

            # module datastore unset
            { mod_set: 0, mod_unset: 1, framework_set: 0, framework_unset: 0, expected: { value: import_default_value, reason: :module_data_store__imported_default, is_default: true } },
            { mod_set: 0, mod_unset: 1, framework_set: 0, framework_unset: 1, expected: { value: import_default_value, reason: :module_data_store__imported_default, is_default: true } },
            { mod_set: 0, mod_unset: 1, framework_set: 1, framework_unset: 0, expected: { value: set_value, reason: :global_data_store__user_defined, is_default: false } },

            # module datastore set
            { mod_set: 1, mod_unset: 0, framework_set: 0, framework_unset: 0, expected: { value: set_value, reason: :module_data_store__user_defined, is_default: false } },
            { mod_set: 1, mod_unset: 0, framework_set: 0, framework_unset: 1, expected: { value: set_value, reason: :module_data_store__user_defined, is_default: false } },
            { mod_set: 1, mod_unset: 0, framework_set: 1, framework_unset: 0, expected: { value: set_value, reason: :module_data_store__user_defined, is_default: false } },
          ].each do |opts|
            context "when #{opts.inspect}" do
              it 'returns the expected value' do
                subject[set_key] = set_value if opts[:mod_set] == 1
                subject.unset(set_key) if opts[:mod_unset] == 1

                framework_datastore[set_key] = set_value if opts[:framework_set] == 1
                framework_datastore.unset(set_key) if opts[:framework_unset] == 1

                # Assertions
                expected = opts[:expected]
                search_result = subject.search_for(read_key)
                expect(search_result.value).to eq expected[:value]
                expect(human_readable_result_for(search_result)).to eq expected[:reason]
                expect(subject[read_key]).to eq expected[:value]
                expect(search_result.default?).to eq(expected[:is_default])
              end
            end
          end
        end
      end
    end

    context 'when the datastore has aliases and fallbacks' do
      subject do
        s = default_subject.copy
        options = Msf::OptionContainer.new(
          [
            Msf::OptString.new(
              'SMBDomain',
              [true, 'The SMB username', 'WORKGROUP'],
              aliases: ['WindowsDomain'],
              fallbacks: ['domain']
            )
          ]
        )
        s.import_options(options)
        s
      end

      context 'when the fallback value is set' do
        before(:each) do
          subject['domain'] = 'domain_fallback'
        end

        it 'supports reading with the option name' do
          expect(subject['SMBDomain']).to eq('domain_fallback')
        end

        it 'supports reading with the alias name' do
          expect(subject['WindowsDomain']).to eq('domain_fallback')
        end
      end

      context 'when the alias and fallback value are set' do
        before(:each) do
          subject['domain'] = 'domain_fallback'
          subject['WindowsDomain'] = 'WindowsDomain'
        end

        it 'supports reading with the option name' do
          expect(subject['SMBDomain']).to eq('WindowsDomain')
        end

        it 'supports reading with the alias name' do
          expect(subject['SMBDomain']).to eq('WindowsDomain')
        end
      end

      # Ensure that both the new name and old name can be used interchangeably, as well as fallbacks
      [
        { set_key: 'SMBDomain', read_key: 'SMBDomain' },
        { set_key: 'WindowsDomain', read_key: 'WindowsDomain' },
        { set_key: 'SMBDomain', read_key: 'WindowsDomain' },
        { set_key: 'WindowsDomain', read_key: 'SMBDomain' },
      ].each do |keys|
        set_key = keys[:set_key]
        read_key = keys[:read_key]

        context "when using #{keys[:set_key].inspect} to set the value and reading with #{keys[:read_key].inspect}" do
          [
            { option_default_value: nil, set_key: set_key, set_value: nil, read_key: read_key },
            { option_default_value: '', set_key: set_key, set_value: nil, read_key: read_key },
            { option_default_value: 'default_value', set_key: set_key, set_value: nil, read_key: read_key },

            { option_default_value: nil, set_key: set_key, set_value: '', read_key: read_key },
            { option_default_value: '', set_key: set_key, set_value: '', read_key: read_key },
            { option_default_value: 'default_value', set_key: set_key, set_value: '', read_key: read_key },

            { option_default_value: nil, set_key: set_key, set_value: 'set_value', read_key: read_key },
            { option_default_value: '', set_key: set_key, set_value: 'set_value', read_key: read_key },
            { option_default_value: 'default_value', set_key: set_key, set_value: 'set_value', read_key: read_key },
          ].each do |test|
            context "when the default value is #{test[:default_value]}" do
              option_default_value = test[:option_default_value]
              set_key = test[:set_key]
              set_value = test[:set_value]
              read_key = test[:set_key] || test[:read_key]

              before(:each) do
                subject.options['SMBDomain'].send(:default=, option_default_value)
              end

              # Test permutations, ints used for readability
              [
                # nothing changed on module
                { mod_set: 0, mod_unset: 0, framework_set: 0, framework_unset: 0, expected: { value: option_default_value, reason: :module_data_store__option_default, is_default: true } },
                { mod_set: 0, mod_unset: 0, framework_set: 0, framework_unset: 1, expected: { value: option_default_value, reason: :module_data_store__option_default, is_default: true } },
                { mod_set: 0, mod_unset: 0, framework_set: 1, framework_unset: 0, expected: { value: set_value, reason: :global_data_store__user_defined, is_default: false } },

                # module datastore unset
                { mod_set: 0, mod_unset: 1, framework_set: 0, framework_unset: 0, expected: { value: option_default_value, reason: :module_data_store__option_default, is_default: true } },
                { mod_set: 0, mod_unset: 1, framework_set: 0, framework_unset: 1, expected: { value: option_default_value, reason: :module_data_store__option_default, is_default: true } },
                { mod_set: 0, mod_unset: 1, framework_set: 1, framework_unset: 0, expected: { value: set_value, reason: :global_data_store__user_defined, is_default: false } },

                # module datastore set
                { mod_set: 1, mod_unset: 0, framework_set: 0, framework_unset: 0, expected: { value: set_value, reason: :module_data_store__user_defined, is_default: false } },
                { mod_set: 1, mod_unset: 0, framework_set: 0, framework_unset: 1, expected: { value: set_value, reason: :module_data_store__user_defined, is_default: false } },
                { mod_set: 1, mod_unset: 0, framework_set: 1, framework_unset: 0, expected: { value: set_value, reason: :module_data_store__user_defined, is_default: false } },
              ].each do |opts|
                context "when #{opts.inspect}" do
                  it 'returns the expected value' do
                    subject[set_key] = set_value if opts[:mod_set] == 1
                    subject.unset(set_key) if opts[:mod_unset] == 1

                    framework_datastore[set_key] = set_value if opts[:framework_set] == 1
                    framework_datastore.unset(set_key) if opts[:framework_unset] == 1

                    # Assertions
                    expected = opts[:expected]
                    search_result = subject.search_for(read_key)
                    expect(search_result.value).to eq expected[:value]
                    expect(human_readable_result_for(search_result)).to eq expected[:reason]
                    expect(subject[read_key]).to eq expected[:value]
                    expect(search_result.default?).to eq(expected[:is_default])
                  end
                end
              end
            end
          end
        end
      end
    end
  end
end

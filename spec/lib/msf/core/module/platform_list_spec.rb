require 'spec_helper'

describe Msf::Module::PlatformList do
  subject(:platform_list) do
    described_class.new(attributes)
  end

  let(:attributes) do
    {}
  end

  context '#&' do
    subject(:ampersand) do
      platform_list & other_platform_list
    end

    let(:other_attributes) do
      {}
    end

    let(:other_platform_list) do
      described_class.new(other_attributes)
    end

    it 'is a new Msf::Module::PlatformList' do
      ampersand.should_not be platform_list
      ampersand.should_not be other_platform_list
    end

    context '#module_class_full_names' do
      subject(:module_class_full_names) do
        ampersand.module_class_full_names
      end

      let(:attributes) do
        {
            module_class_full_names: self_module_class_full_names
        }
      end

      let(:common_module_class_full_names) do
        [
            'first/common/full/module/name',
            'second/common/full/module/name'
        ]
      end


      let(:other_attributes) do
        {
            module_class_full_names: other_module_class_full_names
        }
      end

      let(:other_module_class_full_names) do
        common_module_class_full_names | ['other/full/module/name']
      end

      let(:self_module_class_full_names) do
        common_module_class_full_names | ['self/full/module/name']
      end

      it 'should be union of #module_class_full_names' do
        expect(module_class_full_names).to match_array(
                                               [
                                                   'self/full/module/name',
                                                   'first/common/full/module/name',
                                                   'second/common/full/module/name',
                                                   'other/full/module/name'
                                               ]
                                           )
      end
    end

    context '#platforms' do
      subject(:platforms) do
        ampersand.platforms
      end

      context 'with same' do
        let(:attributes) do
          {
              platforms: platform
          }
        end

        let(:other_attributes) do
          {
              platforms: platform
          }
        end

        let(:platform) do
          Metasploit::Framework::Platform.all.sample
        end

        it 'should be same platform' do
          expect(platforms).to match_array([platform])
        end
      end

      context 'with an ancestor and a descendant' do
        #
        # Methods
        #

        def platform_with_fully_qualified_name(fully_qualified_name)
          Metasploit::Framework::Platform.all.find { |platform|
            platform.fully_qualified_name == fully_qualified_name
          }
        end

        #
        # lets
        #

        let(:ancestor) do
          platform_with_fully_qualified_name('Windows')
        end

        let(:attributes) do
          {
              platforms: ancestor
          }
        end

        let(:descendant) do
          platform_with_fully_qualified_name('Windows XP SP1')
        end

        let(:other_attributes) do
          {
              platforms: descendant
          }
        end

        it 'should be the descendant' do
          expect(platforms).to match_array([descendant])
        end
      end
    end
  end

  context '#from_a' do
    subject(:from_a) do
      described_class.from_a(array, options)
    end

    let(:options) do
      {}
    end

    context 'with Array' do
      #
      # Shared Examples
      #

      shared_examples_for 'from_a' do
        it { should be_a described_class }

        context '#module_class_full_names' do
          subject(:module_class_full_names) do
            from_a.module_class_full_names
          end

          context 'with :module_class_full_names' do
            include_context 'database cleaner'

            let(:expected_module_class_full_names) do
              [module_class.full_name]
            end

            let(:module_class) do
              FactoryGirl.create(:mdm_module_class)
            end

            let(:options) do
              {
                  module_class_full_names: expected_module_class_full_names
              }
            end

            it 'should be :module_class_full_names' do
              module_class_full_names.should == expected_module_class_full_names
            end
          end

          context 'without :module_class_full_names' do
            it { should == [] }
          end
        end

        context '#platforms' do
          subject(:platforms) do
            from_a.platforms
          end

          it 'should be the Metasploit::Framework::Platforms' do
            expect(platforms).to match_array(expected_platforms)
          end
        end
      end

      #
      # lets
      #

      let(:expected_platforms) do
        Metasploit::Framework::Platform.all.sample(2)
      end


      context 'with Metasploit::Framework::Platforms' do
        let(:array) do
          expected_platforms
        end

        it_should_behave_like 'from_a'
      end

      context 'with Metasploit::Framework::Platform#fully_qualified_names' do
        let(:array) do
          expected_platforms.map(&:fully_qualified_name)
        end

        it_should_behave_like 'from_a'
      end

      context 'with Metasploit::Framework::Platform#fully_qualified_name prefixes' do
        let(:array) do
          [
              'win'
          ]
        end

        let(:expected_platforms) do
          Metasploit::Framework::Platform.all.select { |platform|
            platform.fully_qualified_name == 'Windows'
          }
        end

        it_should_behave_like 'from_a'
      end
    end

    context 'without Array' do
      let(:array) do
        Set.new
      end

      specify {
        expect {
          from_a
        }.to raise_error(TypeError)
      }
    end
  end

  context '#initialize' do
    subject(:instance) do
      described_class.new(attributes)
    end

    let(:attributes) do
      {}
    end

    it 'should set #module_class_full_names before #platforms so #module_class_full_names can be used to report deprecation warnings' do
      module_class_full_names_time = nil
      platforms_time = nil

      described_class.any_instance.should_receive(:module_class_full_names=) do
        module_class_full_names_time = Time.now
      end

      described_class.any_instance.should_receive(:platforms=) do
        platforms_time = Time.now
      end

      instance

      module_class_full_names_time.should < platforms_time
    end
  end

  context '#module_class_full_names' do
    subject(:module_class_full_names) do
      platform_list.module_class_full_names
    end

    context 'default' do
      it { should == [] }
    end
  end

  context '#platforms' do
    subject(:platforms) do
      platform_list.platforms
    end

    context 'default' do
      it { should == [] }
    end
  end

  context '#platforms=' do
    subject(:write_platforms) do
      platform_list.platforms = raw_platforms
    end

    let(:raw_platforms) do
      nil
    end

    it 'should reset #platform_and_descendant_set memoizaton' do
      before = double
      platform_list.instance_variable_set :@platform_and_descendant_set, before

      expect {
        write_platforms
      }.to change {
        platform_list.instance_variable_get :@platform_and_descendant_set
      }.to(nil)
    end

    context 'with Array' do
      let(:raw_platforms) do
        Array.new
      end

      it 'should collect all Metasploit::Framework::Platforms using collect_concat' do
        raw_platforms.should_receive(:collect_concat)

        write_platforms
      end
    end

    context 'with Metasploit::Framework::Platform' do
      let(:raw_platforms) do
        Metasploit::Framework::Platform.all.sample
      end

      it 'should include the Metasploit::Framework::Platform' do
        write_platforms

        platform_list.platforms.should include(raw_platforms)
      end
    end

    context 'with Set' do
      let(:raw_platforms) do
        Set.new
      end

      it 'should collect all Metasploit::Framework::Platforms using collect_concat' do
        raw_platforms.should_receive(:collect_concat)

        write_platforms
      end
    end

    context 'with String' do
      context 'with non-empty String' do
        include_context 'database cleaner'

        #
        # lets
        #

        let(:module_class) do
          FactoryGirl.create(:mdm_module_class)
        end

        let(:module_class_full_names) do
          [module_class.full_name]
        end

        let(:raw_platforms) do
          'non-empty-string'
        end

        #
        # Callbacks
        #

        before(:each) do
          platform_list.module_class_full_names = module_class_full_names
        end

        it 'calls Metasploit::Framework::Platform.closest' do
          Metasploit::Framework::Platform.should_receive(:closest).with(
              raw_platforms,
              hash_including(
                  module_class_full_names: module_class_full_names
              )
          )

          write_platforms
        end
      end

      context "with ''" do
        let(:raw_platforms) do
          ''
        end

        it 'should be Metasploit::Framework::Platform.all' do
          write_platforms

          expect(platform_list.platforms).to match_array(Metasploit::Framework::Platform.all)
        end
      end

    end

    context 'with nil' do
      let(:raw_platforms) do
        nil
      end

      it 'should be treated as []' do
        write_platforms

        platform_list.platforms.should == []
      end
    end
  end

  context 'transform' do
    subject(:transform) do
      described_class.transform(src, options)
    end

    let(:module_class_full_names) do
      [double('#module_class_full_names')]
    end

    let(:options) do
      {
          module_class_full_names: module_class_full_names
      }
    end

    let(:src) do
      double('src')
    end

    it 'should Array.wrap src' do
      Array.should_receive(:wrap).with(src).and_return([])

      transform
    end

    it 'calls #from_a' do
      described_class.should_receive(:from_a).with(
          [src],
          hash_including(
              module_class_full_names: module_class_full_names
          )
      )

      transform
    end
  end
end
require 'spec_helper'

describe Metasploit::Framework::Platform do
  subject(:platform) do
    described_class.all.sample
  end

  context 'all' do
    #
    # Shared examples
    #

    shared_examples_for 'caches Metasploit::Framework::Platform' do |options={}|
      options.assert_valid_keys(:child_relative_names, :fully_qualified_name)

      child_relative_names = options[:child_relative_names] || []
      fully_qualified_name = options.fetch(:fully_qualified_name)

      context "with #fully_qualified_name #{fully_qualified_name.inspect}" do
        subject(:platform) do
          all.find { |platform|
            platform.fully_qualified_name == fully_qualified_name
          }
        end

        it "is frozen so that consumer can't interfere with each other" do
          platform.should be_frozen
        end

        it 'memoizes #child_set prior to freezing to prevent RuntimeError' do
          expect {
            platform.child_set
          }.not_to raise_error
        end

        it 'memoizes #depth prior to freezing to prevent RuntimeError' do
          expect {
            platform.depth
          }.not_to raise_error
        end

        it 'memoizes #self_and_descendant_set prior to freezing to prevent RuntimeError' do
          expect {
            platform.self_and_descendant_set
          }.not_to raise_error
        end

        context '#child_set' do
          subject(:child_set) do
            platform.child_set
          end

          context '#relative_name' do
            subject(:relative_names) do
              child_set.map(&:relative_name)
            end

            it { should match_array(child_relative_names) }
          end
        end
      end
    end

    subject(:all) do
      described_class.all
    end

    it { should be_frozen }

    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'AIX'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Android'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'BSD'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'BSDi'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Cisco'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'FreeBSD'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'HPUX'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'IRIX'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Java'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Javascript'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Linux'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'NetBSD'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Netware'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'OSX'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'OpenBSD'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'PHP'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Python'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Ruby'

    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          child_relative_names: [
                              '4',
                              '5',
                              '6',
                              '7',
                              '8',
                              '9',
                              '10'
                          ],
                          fully_qualified_name: 'Solaris' do

    end

    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Solaris 4'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Solaris 5'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Solaris 6'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Solaris 7'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Solaris 8'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Solaris 9'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Solaris 10'

    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'UNIX'

    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          child_relative_names:  [
                              '2000',
                              '2003',
                              '7',
                              '95',
                              '98',
                              'ME',
                              'NT',
                              'Vista',
                              'XP'
                          ],
                          fully_qualified_name: 'Windows'

    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          child_relative_names: [
                              'SP0',
                              'SP1',
                              'SP2',
                              'SP3',
                              'SP4'
                          ],
                          fully_qualified_name: 'Windows 2000'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows 2000 SP0'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows 2000 SP1'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows 2000 SP2'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows 2000 SP3'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows 2000 SP4'

    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          child_relative_names: [
                              'SP0',
                              'SP1'
                          ],
                          fully_qualified_name: 'Windows 2003'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows 2003 SP0'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows 2003 SP1'

    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows 7'

    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows 95'

    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          child_relative_names: [
                              'FE',
                              'SE'
                          ],
                          fully_qualified_name: 'Windows 98'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows 98 FE'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows 98 SE'

    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows ME'

    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          child_relative_names: [
                              'SP0',
                              'SP1',
                              'SP2',
                              'SP3',
                              'SP4',
                              'SP5',
                              'SP6',
                              'SP6a'
                          ],
                          fully_qualified_name: 'Windows NT'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows NT SP0'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows NT SP1'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows NT SP2'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows NT SP3'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows NT SP4'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows NT SP5'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows NT SP6'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows NT SP6a'

    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          child_relative_names: [
                              'SP0',
                              'SP1'
                          ],
                          fully_qualified_name: 'Windows Vista'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows Vista SP0'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows Vista SP1'

    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          child_relative_names: [
                              'SP0',
                              'SP1',
                              'SP2',
                              'SP3'
                          ],
                          fully_qualified_name: 'Windows XP'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows XP SP0'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows XP SP1'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows XP SP2'
    it_should_behave_like 'caches Metasploit::Framework::Platform',
                          fully_qualified_name: 'Windows XP SP3'
  end

  context '#child_set' do
    subject(:child_set) do
      it { should be_a Set }
    end
  end

  context '#closest' do
    #
    # Shared examples
    #

    shared_examples_for 'warns about deprecation' do
      context 'with :module_class_full_names' do
        include_context 'database cleaner'

        let(:module_classes) do
          FactoryGirl.create_list(:mdm_module_class, 2)
        end

        let(:module_class_full_names) do
          module_classes.map(&:full_name)
        end

        let(:options) do
          {
              module_class_full_names: module_class_full_names
          }
        end

        it 'should include location' do
          ActiveSupport::Deprecation.should_receive(:warn) do |message, _callstack|
            module_classes.each do |module_class|
              # have to use different style than code under test
              ancestors = module_class.ancestors

              if ancestors.size == 1
                ancestor_pluralization = 'ancestor'
                ancestor_sentence = "#{ancestors.first.real_path}"
              else
                ancestor_pluralization = 'ancestors'
                real_paths = ancestors.map(&:real_path)
                sorted_real_paths = real_paths.sort
                ancestor_sentence = "#{sorted_real_paths[0]} and #{sorted_real_paths[1]}"
              end

              message.should include(
                                 "module class (#{module_class.full_name}) " \
                                 "defined by its #{ancestor_pluralization} (#{ancestor_sentence})"
                             )
            end
          end

          closest
        end

        it 'should include empty callstack' do
          ActiveSupport::Deprecation.should_receive(:warn).with(an_instance_of(String), [])

          closest
        end
      end

      context 'without :module_class_full_names' do
        it 'should not include location' do
          ActiveSupport::Deprecation.should_receive(:warn) do |message, _callstack|
            message.should == "#{string.inspect} is deprecated as a platform name.  Use #{expected_platform.fully_qualified_name.inspect} instead."
          end

          closest
        end

        it 'should include empty callstack' do
          ActiveSupport::Deprecation.should_receive(:warn).with(an_instance_of(String), [])

          closest
        end
      end
    end

    subject(:closest) do
      described_class.closest(string, options)
    end

    let(:options) do
      {}
    end

    context 'with empty String' do
      let(:string) do
        ''
      end

      specify {
        expect {
          closest
        }.to raise_error(ArgumentError)
      }
    end

    context 'with exact match' do
      let(:expected_platform) do
        described_class.all.sample
      end

      let(:string) do
        expected_platform.fully_qualified_name
      end

      it 'returns matching platform' do
        closest.should == expected_platform
      end

      it 'should not issue a deprecation warning' do
        ActiveSupport::Deprecation.should_not_receive(:warn)

        closest
      end
    end

    context 'with case-insensitive match' do
      let(:expected_platform) do
        described_class.all.sample
      end

      let(:string) do
        expected_platform.fully_qualified_name.downcase
      end

      it 'returns matching platform' do
        closest.should == expected_platform
      end

      it_should_behave_like 'warns about deprecation'
    end

    context 'with prefix match' do
      let(:expected_platform) do
        described_class.all.find { |platform|
          platform.fully_qualified_name == 'Windows'
        }
      end

      let(:string) do
        'win'
      end

      it 'returns matching platform' do
        closest.should == expected_platform
      end

      it_should_behave_like 'warns about deprecation'
    end

    context 'with prefix collision' do
      let(:string) do
        # java or javascript
        'j'
      end

      specify {
        expect {
          closest
        }.to raise_error(ArgumentError)
      }
    end

    context 'without match' do
      let(:string) do
        'non_matching_string'
      end

      specify {
        expect {
          closest
        }.to raise_error(ArgumentError)
      }
    end

    context 'with compact match' do
      let(:expected_platform) do
        described_class.all.find { |platform|
          platform.fully_qualified_name == 'Windows 95'
        }
      end

      let(:string) do
        'win95'
      end

      it 'should match platform' do
        closest.should == expected_platform
      end

      it_should_behave_like 'warns about deprecation'
    end
  end

  context '#depth' do
    subject(:depth) do
      platform.depth
    end

    let(:platform) do
      platforms.sample
    end

    context 'with #parent' do
      let(:parent) do
        platform.parent
      end

      let(:platforms) do
        described_class.all.select(&:parent)
      end

      it 'should be one more than #parent #depth' do
        depth.should == (parent.depth + 1)
      end
    end

    context 'without #parent' do
      let(:platforms) do
        described_class.all.reject(&:parent)
      end

      it { should == 0 }
    end
  end

  context '#self_and_descendant_set' do
    subject(:self_and_descendant_set) do
      platform.self_and_descendant_set
    end

    it { should be_a Set }

    it 'should include self' do
      self_and_descendant_set.should include(platform)
    end

    context 'with children' do
      let(:platform) do
        platforms.sample
      end

      let(:platforms) do
        described_class.all.select { |platform|
          !platform.child_set.empty?
        }
      end

      it 'should include #self_and_descendant_set each child' do
        platform.child_set.each do |child|
          self_and_descendant_set.should be_superset(child.self_and_descendant_set)
        end
      end
    end
  end
end
require 'spec_helper'

describe Msf::Module::SiteReference do
  subject(:site_reference) do
    described_class.new
  end

  context '#extension' do
    subject(:extension) do
      site_reference.send(:extension)
    end

    before(:each) do
      allow(site_reference).to receive(:extension_name).and_return(extension_name)
    end

    context 'with #extension_name' do
      context 'with defined Module' do
        let(:expected_extension) do
          Metasploit::Model::Authority::Cve
        end

        let(:extension_name) do
          expected_extension.name
        end

        it 'is Module with Module#name equal to #extension_name' do
          expect(extension).to eq(expected_extension)
        end
      end

      context 'without defined Module' do
        let(:extension_name) do
          'Not::A::Defined::Module'
        end

        it { should be_nil }
      end
    end

    context 'without #extension_name' do
      let(:extension_name) do
        nil
      end

      it { should be_nil }
    end
  end

  context '#extension_name' do
    subject(:extension_name) do
      site_reference.send(:extension_name)
    end

    before(:each) do
      site_reference.send(:ctx_id=, ctx_id)
    end

    context 'with ctx_id' do
      context "with '-'" do
        let(:ctx_id) do
          'With-Dash'
        end

        it "removes '-'" do
          expect(extension_name).to eq('Metasploit::Model::Authority::WithDash')
        end
      end

      context "with ALLCAPS" do
        let(:ctx_id) do
          'ALLCAPS'
        end

        it 'camelizes' do
          expect(extension_name).to eq('Metasploit::Model::Authority::Allcaps')
        end
      end
    end

    context 'without ctx_id' do
      let(:ctx_id) do
        ''
      end

      it { should be_nil }
    end
  end

  context 'from_a' do
    subject(:from_a) do
      described_class.from_a(array)
    end

    context 'with 2 elements' do
      let(:array) do
        [
            'context_id',
            'context_value'
        ]
      end

      it 'calls new with *array' do
        expect(described_class).to receive(:new).with(*array)

        from_a
      end
    end

    context 'without 2 elements' do
      let(:array) do
        [
            'one element'
        ]
      end

      it { should be_nil }
    end
  end

  context 'from_s' do
    subject(:from_s) do
      described_class.from_s(string)
    end

    let(:string) do
      'a string'
    end

    context '#from_s' do
      before(:each) do
        described_class.any_instance.should_receive(:from_s).with(string).and_return(from_s_return)
      end

      context 'returns false' do
        let(:from_s_return) do
          false
        end

        it { should be_nil }
      end

      context 'returns true' do
        let(:from_s_return) do
          true
        end

        it { should be_a described_class }
      end
    end
  end

  context '#initialize' do
    subject(:initialize) do
      described_class.new(*arguments)
    end

    let(:arguments) do
      [
          'Unknown',
          ''
      ]
    end

    context 'without arguments' do
      let(:arguments) do
        []
      end

      its(:ctx_id) { should == 'Unknown' }
      its(:ctx_val) { should == '' }
    end

    context 'with one argument' do
      let(:arguments) do
        [
            expected_ctx_id
        ]
      end

      let(:expected_ctx_id) do
        'expected_ctx_id'
      end

      it 'uses first argument as #ctx_id' do
        expect(initialize.ctx_id).to eq(expected_ctx_id)
      end

      its(:ctx_val) { should == '' }
    end

    context 'with two arguments' do
      let(:arguments) do
        [
            expected_ctx_id,
            expected_ctx_val
        ]
      end

      let(:expected_ctx_id) do
        'expected_ctx_id'
      end

      let(:expected_ctx_val) do
        'expected_ctx_val'
      end

      it 'uses first argument as #ctx_id' do
        expect(initialize.ctx_id).to eq(expected_ctx_id)
      end

      it 'uses second argument as #ctx_val' do
        expect(initialize.ctx_val).to eq(expected_ctx_val)
      end
    end
  end

  context '#to_s' do
    subject(:to_s) do
      site_reference.to_s
    end

    before(:each) do
      allow(site_reference).to receive(:site).and_return(site)
    end

    context 'with #site' do
      let(:site) do
        'http://example.com'
      end

      it 'uses #site' do
        expect(to_s).to eq(site)
      end
    end

    context 'without #site' do
      let(:site) do
        nil
      end

      it { should == '' }
    end
  end

  context '#from_s' do
    #
    # Shared examples
    #

    shared_examples_for 'scheme' do |scheme|
      context "with #{scheme}://" do
        let(:scheme) do
          scheme
        end

        it { should be_true }

        it "uses 'URL' for #ctx_id" do
          from_s

          expect(site_reference.ctx_id).to eq('URL')
        end

        it 'uses string for #ctx_val' do
          from_s

          expect(site_reference).to eq(string)
        end

        it 'uses string for #site' do
          from_s

          expect(site_reference.site).to eq(string)
        end
      end
    end

    subject(:from_s) do
      site_reference.from_s(string)
    end

    #
    # lets
    #

    let(:host) do
      'example.com'
    end

    let(:string) do
      "#{scheme}://#{host}"
    end

    it_should_behave_like 'scheme', 'ftp'
    it_should_behave_like 'scheme', 'http'
    it_should_behave_like 'scheme', 'https'

    context 'with unrecognized scheme' do
      let(:scheme) do
        'magnet'
      end

      it { should be_false }

      it 'does not change #ctx_id' do
        expect {
          from_s
        }.not_to change(site_reference, :ctx_id)
      end

      it 'does not change #ctx_val' do
        expect {
          from_s
        }.not_to change(site_reference, :ctx_val)
      end

      it 'does not change #site' do
        expect {
          from_s
        }.not_to change(site_reference, :site)
      end
    end
  end

  context '#site' do
    subject(:site) do
      site_reference.site
    end

    before(:each) do
      site_reference.send(:ctx_id=, ctx_id)
      site_reference.send(:ctx_val=, ctx_val)

      allow(site_reference).to receive(:extension).and_return(extension)
    end

    context 'with #extension' do
      let(:extension) do
        Module.new do
          def self.designation_url(designation)
            "http://authority.com/#{designation}"
          end
        end
      end

      let(:ctx_id) do
        FactoryGirl.generate :metasploit_model_authority_abbreviation
      end

      let(:ctx_val) do
        FactoryGirl.generate :metasploit_model_reference_designation
      end

      it 'sets #site to ::designation_url of extension' do
        expect(site).to eq(extension.designation_url(ctx_val))
      end
    end

    context 'without #extension' do
      let(:extension) do
        nil
      end

      context "with 'URL' #ctx_id" do
        let(:ctx_id) do
          'URL'
        end

        let(:ctx_val) do
          FactoryGirl.generate :metasploit_model_reference_url
        end

        it 'sets #site to #ctx_val' do
          expect(site).to eq(ctx_val)
        end
      end

      context "without 'URL' #ctx_id" do
        let(:ctx_id) do
          'UNKNOWN_CONTEXT'
        end

        context 'with #ctx_val' do
          let(:ctx_val) do
            'UNKNOWN_VALUE'
          end

          it "sets #site to '<ctx_id> (<ctx_val)'" do
            expect(site).to eq("#{ctx_id} (#{ctx_val})")
          end
        end

        context 'without #ctx_val' do
          let(:ctx_val) do
            ''
          end

          it 'sets #site to #ctx_id' do
            expect(site).to eq(ctx_id)
          end
        end
      end
    end
  end
end
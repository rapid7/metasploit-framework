load Metasploit::Framework.root.join('tools/msu_finder.rb').to_path

describe MicrosoftPatch do

  describe MicrosoftPatch::SiteInfo do
    context 'Constants' do
      context 'TECHNET' do
        let(:technet) do
          MicrosoftPatch::SiteInfo::TECHNET
        end

        it 'returns 157.56.148.23 as the IP' do
          expect(technet[:ip]).to eq('157.56.148.23')
        end

        it 'returns technet.microsoft.com as the vhost' do
          expect(technet[:vhost]).to eq('technet.microsoft.com')
        end
      end

      context 'MICROSOFT' do
        let(:microsoft) do
          MicrosoftPatch::SiteInfo::MICROSOFT
        end

        it 'returns 104.72.230.162 as the IP' do
          expect(microsoft[:ip]).to eq('104.72.230.162')
        end

        it 'returns www.microsoft.com as the vhost' do
          expect(microsoft[:vhost]).to eq('www.microsoft.com')
        end
      end

      context 'GOOGLEAPIS' do
        let(:googleapis) do
          MicrosoftPatch::SiteInfo::GOOGLEAPIS
        end

        it 'returns 74.125.28.95 as the IP' do
          expect(googleapis[:ip]).to eq('74.125.28.95')
        end

        it 'returns www.googleapis.com as the vhost' do
          expect(googleapis[:vhost]).to eq('www.googleapis.com')
        end
      end
    end
  end

  describe MicrosoftPatch::Base do
  end

  describe MicrosoftPatch::PatchLinkCollector do
  end

  describe MicrosoftPatch::TechnetMsbSearch do
  end

  describe MicrosoftPatch::GoogleMsbSearch do
  end

  describe MicrosoftPatch::Module do
  end

end
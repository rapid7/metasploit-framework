load Metasploit::Framework.root.join('tools/msu_finder.rb').to_path

require 'nokogiri'
require 'uri'

describe MicrosoftPatch do

  before(:each) do
    cli = Rex::Proto::Http::Client.new('127.0.0.1')
    allow(cli).to receive(:connect)
    allow(cli).to receive(:request_cgi)
    allow(cli).to receive(:send_recv).and_return(Rex::Proto::Http::Response.new)
    allow(Rex::Proto::Http::Client).to receive(:new).and_return(cli)
  end

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

    def get_stdout(&block)
      out = $stdout
      $stdout = fake = StringIO.new
      begin
        yield
      ensure
        $stdout = out
      end
      fake.string
    end

    def get_stderr(&block)
      out = $stderr
      $stderr = fake = StringIO.new
      begin
        yield
      ensure
        $stderr = out
      end
      fake.string
    end

    subject do
      MicrosoftPatch::Base.new
    end

    describe '#print_debug' do
      it 'prints a [DEBUG] message' do
        output = get_stderr { subject.print_debug }
        expect(output).to include('[DEBUG]')
      end
    end

    describe '#print_status' do
      it 'prints a [*] message' do
        output = get_stderr { subject.print_status }
        expect(output).to include('[*]')
      end
    end

    describe '#print_error' do
      it 'prints an [ERROR] message' do
        output = get_stderr { subject.print_error }
        expect(output).to include('[ERROR]')
      end
    end

    describe '#print_line' do
      it 'prints a regular message' do
        msg = 'TEST'
        output = get_stdout { subject.print_line(msg) }
        expect(output).to eq("#{msg}\n")
      end
    end

    describe '#send_http_request' do
      it 'returns a Rex::Proto::Http::Response object' do
        allow(subject).to receive(:print_debug)
        res = subject.send_http_request(MicrosoftPatch::SiteInfo::TECHNET)
        expect(res).to be_kind_of(Rex::Proto::Http::Response)
      end
    end

  end

  describe MicrosoftPatch::PatchLinkCollector do

    let(:ms15_100_html) do
      %Q|
      <html>
      <div id="mainBody">
        <div>
          <h2>
          <div>
            <span>Affected Software</span>
            <div class="sectionblock">
              <table>
              <tr><td><a href="https://www.microsoft.com/downloads/details.aspx?familyid=1">fake link</a></td></tr>
              </table>
            </div>
          </div>
          </h2>
        </div>
      </div>
      </html>
      |
    end

    let(:ms07_029_html) do
      %Q|
      <html>
      <div id="mainBody">
        <ul>
          <li>
            <a href="http://technet.microsoft.com">Download the update</a>
          </li>
        </ul>
      </div>
      </html>
      |
    end

    let(:ms03_039_html) do
      %Q|
      <html>
      <div id="mainBody">
        <div>
          <div class="sectionblock">
            <p>
              <strong>Download locations</strong>
            </p>
            <ul>
              <li>
                <a href="http://technet.microsoft.com">Download</a>
              </li>
            </ul>
          </div>
        </div>
      </div>
      </html>
      |
    end

    let(:ms07_030_html) do
      %Q|
      <html>
      <div id="mainBody">
        <p>
          <strong>Affected Software</strong>
        </p>
        <table>
        <tr><td><a href="http://technet.microsoft.com">Download</a></td></tr>
      </div>
      </html>
      |
    end

    subject do
      MicrosoftPatch::PatchLinkCollector.new
    end

    before(:each) do
      allow(subject).to receive(:print_debug)
    end

    describe '#download_advisory' do
      it 'returns a Rex::Proto::Http::Response object' do
        res = subject.download_advisory('ms15-100')
        expect(res).to be_kind_of(Rex::Proto::Http::Response)
      end
    end

    describe '#get_appropriate_pattern' do

      it 'returns a pattern for ms15-100' do
        expected_pattern = '//div[@id="mainBody"]//div//div[@class="sectionblock"]//table//a'
        p = subject.get_appropriate_pattern(::Nokogiri::HTML(ms15_100_html))
        expect(p).to eq(expected_pattern)
      end

      it 'returns a pattern for ms07-029' do
        expected_pattern = '//div[@id="mainBody"]//ul//li//a[contains(text(), "Download the update")]'
        p = subject.get_appropriate_pattern(::Nokogiri::HTML(ms07_029_html))
        expect(p).to eq(expected_pattern)
      end

      it 'returns a pattern for ms03-039' do
        expected_pattern = '//div[@id="mainBody"]//div//div[@class="sectionblock"]//ul//li//a'
        p = subject.get_appropriate_pattern(::Nokogiri::HTML(ms03_039_html))
        expect(p).to eq(expected_pattern)
      end

      it 'returns a pattern for ms07-030' do
        expected_pattern = '//div[@id="mainBody"]//table//a'
        p = subject.get_appropriate_pattern(::Nokogiri::HTML(ms07_030_html))
        expect(p).to eq(expected_pattern)
      end
    end

    describe '#get_details_aspx' do
      let(:details_aspx) do
        res = Rex::Proto::Http::Response.new
        allow(res).to receive(:body).and_return(ms15_100_html)
        res
      end

      it 'returns an URI object to a details aspx' do
        links = subject.get_details_aspx(details_aspx)
        expected_uri = 'https://www.microsoft.com/downloads/details.aspx?familyid=1'
        expect(links.length).to eq(1)
        expect(links.first).to be_kind_of(URI)
        expect(links.first.to_s).to eq(expected_uri)
      end
    end

    describe '#follow_redirect' do
    end

    describe '#get_download_page' do
    end

    describe '#get_download_links' do
    end

    describe '#has_advisory?' do
    end

    describe '#is_valid_msb?' do
    end

  end

  describe MicrosoftPatch::TechnetMsbSearch do

    describe '#find_msb_numbers' do
    end

    describe '#search' do
    end

    describe '#search_by_product_ids' do
    end

    describe '#search_by_keyword' do
    end

    describe '#get_product_dropdown_list' do
    end

  end

  describe MicrosoftPatch::GoogleMsbSearch do

    describe '#find_msb_numbers' do
    end

    describe '#search' do
    end

    describe '#parse_results' do
    end

    describe '#get_total_results' do
    end

    describe '#get_next_index' do
    end

  end

  describe MicrosoftPatch::Module do

    describe '#get_download_links' do
    end

    describe '#google_search' do
    end

    describe '#technet_search' do
    end

    describe '#run' do
    end

  end

end

load Metasploit::Framework.root.join('tools/exploit/msu_finder.rb').to_path

require 'nokogiri'
require 'uri'

RSpec.describe MicrosoftPatchFinder do

  before(:each) do
    cli = Rex::Proto::Http::Client.new('127.0.0.1')
    allow(cli).to receive(:connect)
    allow(cli).to receive(:request_cgi)
    allow(cli).to receive(:send_recv).and_return(Rex::Proto::Http::Response.new)
    allow(Rex::Proto::Http::Client).to receive(:new).and_return(cli)
  end

  let(:technet) do
    MicrosoftPatchFinder::SiteInfo::TECHNET
  end

  let(:microsoft) do
    MicrosoftPatchFinder::SiteInfo::MICROSOFT
  end

  let(:googleapis) do
    MicrosoftPatchFinder::SiteInfo::GOOGLEAPIS
  end

  describe MicrosoftPatchFinder::SiteInfo do
    context 'Constants' do
      context 'TECHNET' do
        it 'returns 157.56.148.23 as the IP' do
          expect(technet[:ip]).to eq('157.56.148.23')
        end

        it 'returns technet.microsoft.com as the vhost' do
          expect(technet[:vhost]).to eq('technet.microsoft.com')
        end
      end

      context 'MICROSOFT' do
        it 'returns 104.72.230.162 as the IP' do
          expect(microsoft[:ip]).to eq('104.72.230.162')
        end

        it 'returns www.microsoft.com as the vhost' do
          expect(microsoft[:vhost]).to eq('www.microsoft.com')
        end
      end

      context 'GOOGLEAPIS' do
        it 'returns 74.125.28.95 as the IP' do
          expect(googleapis[:ip]).to eq('74.125.28.95')
        end

        it 'returns www.googleapis.com as the vhost' do
          expect(googleapis[:vhost]).to eq('www.googleapis.com')
        end
      end
    end
  end

  describe MicrosoftPatchFinder::Helper do

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

    subject(:object_helper) do
      mod = Object.new
      mod.extend MicrosoftPatchFinder::Helper
      mod
    end

    describe '#print_debug' do
      it 'prints a [DEBUG] message' do
        output = get_stderr { object_helper.print_debug }
        expect(output).to include('[DEBUG]')
      end
    end

    describe '#print_status' do
      it 'prints a [*] message' do
        output = get_stderr { object_helper.print_status }
        expect(output).to include('[*]')
      end
    end

    describe '#print_error' do
      it 'prints an [ERROR] message' do
        output = get_stderr { object_helper.print_error }
        expect(output).to include('[ERROR]')
      end
    end

    describe '#print_line' do
      it 'prints a regular message' do
        msg = 'TEST'
        output = get_stdout { object_helper.print_line(msg) }
        expect(output).to eq("#{msg}\n")
      end
    end

    describe '#send_http_request' do
      it 'returns a Rex::Proto::Http::Response object' do
        allow(object_helper).to receive(:print_debug)
        res = object_helper.send_http_request(MicrosoftPatchFinder::SiteInfo::TECHNET)
        expect(res).to be_kind_of(Rex::Proto::Http::Response)
      end
    end

  end

  describe MicrosoftPatchFinder::PatchLinkCollector do

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

    subject(:patch_link_collector) do
      MicrosoftPatchFinder::PatchLinkCollector.new
    end

    before(:each) do
      allow(patch_link_collector).to receive(:print_debug)
    end

    describe '#download_advisory' do
      it 'returns a Rex::Proto::Http::Response object' do
        res = patch_link_collector.download_advisory('ms15-100')
        expect(res).to be_kind_of(Rex::Proto::Http::Response)
      end
    end

    describe '#get_appropriate_pattern' do

      it 'returns a pattern for ms15-100' do
        expected_pattern = '//div[@id="mainBody"]//div//div[@class="sectionblock"]//table//a'
        p = patch_link_collector.get_appropriate_pattern(::Nokogiri::HTML(ms15_100_html))
        expect(p).to eq(expected_pattern)
      end

      it 'returns a pattern for ms07-029' do
        expected_pattern = '//div[@id="mainBody"]//ul//li//a[contains(text(), "Download the update")]'
        p = patch_link_collector.get_appropriate_pattern(::Nokogiri::HTML(ms07_029_html))
        expect(p).to eq(expected_pattern)
      end

      it 'returns a pattern for ms03-039' do
        expected_pattern = '//div[@id="mainBody"]//div//div[@class="sectionblock"]//ul//li//a'
        p = patch_link_collector.get_appropriate_pattern(::Nokogiri::HTML(ms03_039_html))
        expect(p).to eq(expected_pattern)
      end

      it 'returns a pattern for ms07-030' do
        expected_pattern = '//div[@id="mainBody"]//table//a'
        p = patch_link_collector.get_appropriate_pattern(::Nokogiri::HTML(ms07_030_html))
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
        links = patch_link_collector.get_details_aspx(details_aspx)
        expected_uri = 'https://www.microsoft.com/downloads/details.aspx?familyid=1'
        expect(links.length).to eq(1)
        expect(links.first).to be_kind_of(URI)
        expect(links.first.to_s).to eq(expected_uri)
      end
    end

    describe '#follow_redirect' do
      let(:expected_header) do
        { 'Location' => 'http://example.com/' }
      end

      let(:http_res) do
        res = Rex::Proto::Http::Response.new
        allow(res).to receive(:headers).and_return(expected_header)
        res
      end

      it 'goes to a location based on the Location HTTP header' do
        cli = Rex::Proto::Http::Client.new('127.0.0.1')
        allow(cli).to receive(:connect)
        allow(cli).to receive(:request_cgi)
        allow(cli).to receive(:send_recv).and_return(http_res)
        allow(Rex::Proto::Http::Client).to receive(:new).and_return(cli)

        expect(patch_link_collector.follow_redirect(technet, http_res).headers).to eq(expected_header)
      end
    end

    describe '#get_download_page' do
      it 'returns a Rex::Proto::Http::Response object' do
        uri = URI('http://www.example.com/')
        expect(patch_link_collector.get_download_page(uri)).to be_kind_of(Rex::Proto::Http::Response)
      end
    end

    describe '#get_download_links' do
      let(:confirm_aspx) do
        %Q|
        <html>
        <a href="https://www.microsoft.com/en-us/download/confirmation.aspx?id=1">Download</a>
        </html>
        |
      end

      let(:expected_link) do
        'http://download.microsoft.com/download/9/0/6/906BC7A4-7DF7-4C24-9F9D-3E801AA36ED3/Windows6.0-KB3087918-x86.msu'
      end

      let(:download_html_res) do
        Rex::Proto::Http::Response.new.tap { |response|
          allow(response).to receive(:body).and_return(
                               %Q|
                               <html>
                                 <a href="#{expected_link}">Click here</a>
                               </html>
                               |
                             )
        }
      end

      it 'returns an array of links' do
        cli = Rex::Proto::Http::Client.new('127.0.0.1')
        allow(cli).to receive(:connect)
        allow(cli).to receive(:request_cgi)
        allow(cli).to receive(:send_recv).and_return(download_html_res)
        allow(Rex::Proto::Http::Client).to receive(:new).and_return(cli)

        expect(patch_link_collector.get_download_links(confirm_aspx).first).to eq(expected_link)
      end
    end

    describe '#has_advisory?' do
      it 'returns true if the page is found' do
        res = Rex::Proto::Http::Response.new
        expect(patch_link_collector.has_advisory?(res)).to be_truthy
      end

      it 'returns false if the page is not found' do
        html = %Q|
        <html>
        We are sorry. The page you requested cannot be found
        </html>
        |

        res = Rex::Proto::Http::Response.new
        allow(res).to receive(:body).and_return(html)
        expect(patch_link_collector.has_advisory?(res)).to be_falsey
      end
    end

    describe '#is_valid_msb?' do
      let(:good_msb) do
        'MS15-100'
      end

      let(:bad_msb) do
        'MS15-01'
      end

      it 'returns true if the MSB format is correct' do
        expect(patch_link_collector.is_valid_msb?(good_msb)).to be_truthy
      end

      it 'returns false if the MSB format is incorrect' do
        expect(patch_link_collector.is_valid_msb?(bad_msb)).to be_falsey
      end

    end

  end

  describe MicrosoftPatchFinder::TechnetMsbSearch do

    subject(:technet_msb_search) do
      MicrosoftPatchFinder::TechnetMsbSearch.new
    end

    before(:each) do
      allow_any_instance_of(MicrosoftPatchFinder::TechnetMsbSearch).to receive(:print_debug)
      allow_any_instance_of(MicrosoftPatchFinder::TechnetMsbSearch).to receive(:send_http_request) { |info_obj, info_opts, opts|
        case opts['uri']
        when /\/en\-us\/security\/bulletin\/dn602597\.aspx/
          html = %Q|
          <div class="sb-search">
          <div class="SearchBox">
          <input type="text" id="txtSearch" title="Search Security Bulletins" value="Search Security Bulletins" />
          <input type="button" id="btnSearch" />
          </div>
          <select id="productDropdown">
          <option value="-1">All</option>
          <option value="10175">Active Directory</option>
          <option value="10401">Windows Internet Explorer 10</option>
          <option value="10486">Windows Internet Explorer 11</option>
          <option value="1282">Windows Internet Explorer 7</option>
          <option value="1233">Windows Internet Explorer 8</option>
          <option value="10054">Windows Internet Explorer 9</option>
          </select>
          </div>
          |
        when /\/security\/bulletin\/services\/GetBulletins/
          html = %Q|{
            "l":1,
            "b":[
              {
                "d":"9/8/2015",
                "Id":"MS15-100",
                "KB":"3087918",
                "Title":"Vulnerability in Windows Media Center Could Allow Remote Code Execution",
                "Rating":"Important"
              }
            ]
          }
          |
        else
          html = ''
        end

        res = Rex::Proto::Http::Response.new
        allow(res).to receive(:body).and_return(html)
        res
      }
    end

    let(:ie10) do
      'Windows Internet Explorer 10'
    end

    let(:ie10_id) do
      10401
    end

    describe '#find_msb_numbers' do
      it 'returns an array of found MSB numbers' do
        msb = technet_msb_search.find_msb_numbers(ie10)
        expect(msb).to be_kind_of(Array)
        expect(msb.first).to eq('ms15-100')
      end
    end

    describe '#search' do
      it 'returns search results in JSON format' do
        results = technet_msb_search.search(ie10)
        expect(results).to be_kind_of(Hash)
        expect(results['b'].first['Id']).to eq('MS15-100')
      end
    end

    describe '#search_by_product_ids' do
      it 'returns an array of found MSB numbers' do
        results = technet_msb_search.search_by_product_ids([ie10_id])
        expect(results).to be_kind_of(Array)
        expect(results.first).to eq('ms15-100')
      end
    end

    describe '#search_by_keyword' do
      it 'returns an array of found MSB numbers' do
        results = technet_msb_search.search_by_keyword('ms15-100')
        expect(results).to be_kind_of(Array)
        expect(results.first).to eq('ms15-100')
      end
    end

    describe '#get_product_dropdown_list' do
      it 'returns an array of products' do
        results = technet_msb_search.get_product_dropdown_list
        expect(results).to be_kind_of(Array)
        expect(results.first).to be_kind_of(Hash)
        expected_hash = {:option_value=>"10175", :option_text=>"Active Directory"}
        expect(results.first).to eq(expected_hash)
      end
    end

  end

  describe MicrosoftPatchFinder::GoogleMsbSearch do

    subject(:google_msb_search) do
      MicrosoftPatchFinder::GoogleMsbSearch.new
    end

    let(:json_data) do
      %Q|{
 "kind": "customsearch#search",
 "url": {
  "type": "application/json",
  "template": ""
 },
 "queries": {
  "request": [
   {
    "title": "Google Custom Search - internet",
    "totalResults": "1",
    "searchTerms": "internet",
    "count": 10,
    "startIndex": 1,
    "inputEncoding": "utf8",
    "outputEncoding": "utf8",
    "safe": "off",
    "cx": ""
   }
  ]
 },
 "context": {
  "title": "Technet.microsoft"
 },
 "searchInformation": {
  "searchTime": 0.413407,
  "formattedSearchTime": "0.41",
  "totalResults": "1",
  "formattedTotalResults": "1"
 },
 "items": [
  {
   "kind": "customsearch#result",
   "title": "Microsoft Security Bulletin MS15-093 - Critical",
   "htmlTitle": "Microsoft Security Bulletin MS15-093 - Critical",
   "link": "https://technet.microsoft.com/en-us/library/security/ms15-093.aspx",
   "displayLink": "technet.microsoft.com",
   "snippet": "",
   "htmlSnippet": "",
   "cacheId": "2xDJB6zqL_sJ",
   "formattedUrl": "https://technet.microsoft.com/en-us/library/security/ms15-093.aspx",
   "htmlFormattedUrl": "https://technet.microsoft.com/en-us/library/security/ms15-093.aspx",
   "pagemap": {
    "metatags": [
     {
      "search.mshkeyworda": "ms15-093",
      "search.mshattr.assetid": "ms15-093",
      "search.mshattr.docset": "bulletin",
      "search.mshattr.sarticletype": "bulletin",
      "search.mshattr.sarticleid": "MS15-093",
      "search.mshattr.sarticletitle": "Security Update for Internet Explorer",
      "search.mshattr.sarticledate": "2015-08-20",
      "search.mshattr.sarticleseverity": "Critical",
      "search.mshattr.sarticleversion": "1.1",
      "search.mshattr.sarticlerevisionnote": "",
      "search.mshattr.sarticleseosummary": "",
      "search.mshattr.skbnumber": "3088903",
      "search.mshattr.prefix": "MSRC",
      "search.mshattr.topictype": "kbOrient",
      "search.mshattr.preferredlib": "/library/security",
      "search.mshattr.preferredsitename": "TechNet",
      "search.mshattr.docsettitle": "MSRC Document",
      "search.mshattr.docsetroot": "Mt404691",
      "search.save": "history",
      "search.microsoft.help.id": "ms15-093",
      "search.description": "",
      "search.mscategory": "dn567670",
      "search.mscategoryv": "dn567670Security10",
      "search.tocnodeid": "mt404691",
      "mshkeyworda": "ms15-093",
      "mshattr": "AssetID:ms15-093",
      "save": "history",
      "microsoft.help.id": "ms15-093"
     }
    ]
   }
  }
 ]
}
        |
    end

    before(:each) do
      allow_any_instance_of(MicrosoftPatchFinder::GoogleMsbSearch).to receive(:print_debug)
      allow_any_instance_of(MicrosoftPatchFinder::GoogleMsbSearch).to receive(:send_http_request) { |info_obj, info_opts, opts|
        res = Rex::Proto::Http::Response.new
        allow(res).to receive(:body).and_return(json_data)
        res
      }
    end

    let(:expected_msb) do
      'ms15-093'
    end

    describe '#find_msb_numbers' do
      it 'returns an array of msb numbers' do
        results = google_msb_search.find_msb_numbers(expected_msb)
        expect(results).to be_kind_of(Array)
        expect(results).to eq([expected_msb])
      end
    end

    describe '#search' do
      it 'returns a hash (json data)' do
        results = google_msb_search.search(starting_index: 1)
        expect(results).to be_kind_of(Hash)
      end
    end

    describe '#parse_results' do
      it 'returns a hash (json data)' do
        res = Rex::Proto::Http::Response.new
        allow(res).to receive(:body).and_return(json_data)

        results = google_msb_search.parse_results(res)
        expect(results).to be_kind_of(Hash)
      end
    end

    describe '#get_total_results' do
      it 'returns a fixnum' do
        total = google_msb_search.get_total_results(JSON.parse(json_data))
        expect(total).to be_kind_of(Fixnum)
      end
    end

    describe '#get_next_index' do
      it 'returns a fixnum' do
        i = google_msb_search.get_next_index(JSON.parse(json_data))
        expect(i).to be_kind_of(Fixnum)
      end
    end

  end

  describe MicrosoftPatchFinder::Driver do

    let(:msb) do
      'ms15-100'
    end

    let(:expected_link) do
      'http://download.microsoft.com/download/9/0/6/906BC7A4-7DF7-4C24-9F9D-3E801AA36ED3/Windows6.0-KB3087918-x86.msu'
    end

    before(:each) do
      opts = { keyword: msb }
      allow(MicrosoftPatchFinder::OptsConsole).to receive(:get_parsed_options).and_return(opts)
      allow_any_instance_of(MicrosoftPatchFinder::PatchLinkCollector).to receive(:download_advisory).and_return(Rex::Proto::Http::Response.new)
      allow_any_instance_of(MicrosoftPatchFinder::PatchLinkCollector).to receive(:get_details_aspx).and_return([expected_link])
      allow_any_instance_of(MicrosoftPatchFinder::PatchLinkCollector).to receive(:get_download_page).and_return(Rex::Proto::Http::Response.new)
      allow_any_instance_of(MicrosoftPatchFinder::PatchLinkCollector).to receive(:get_download_links).and_return([expected_link])
      allow_any_instance_of(MicrosoftPatchFinder::Driver).to receive(:print_debug)
      allow_any_instance_of(MicrosoftPatchFinder::Driver).to receive(:print_error)
      allow_any_instance_of(MicrosoftPatchFinder::PatchLinkCollector).to receive(:print_debug)
      allow_any_instance_of(MicrosoftPatchFinder::PatchLinkCollector).to receive(:print_error)
    end

    subject(:driver) do
      MicrosoftPatchFinder::Driver.new
    end

    describe '#get_download_links' do
      it 'returns an array of links' do
        results = driver.get_download_links(msb)
        expect(results).to be_kind_of(Array)
        expect(results.first).to eq(expected_link)
      end
    end

    describe '#google_search' do
      it 'returns search results' do
        skip('See rspec for MicrosoftPatchFinder::GoogleMsbSearch#find_msb_numbers')
      end
    end

    describe '#technet_search' do
      it 'returns search results' do
        skip('See rspec for MicrosoftPatchFinder::TechnetMsbSearch#find_msb_numbers')
      end
    end

  end

end

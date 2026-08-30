require 'spec_helper'
require 'rex/parser/acunetix_document'

RSpec.describe Rex::Parser::AcunetixDocument do

  if ENV['REMOTE_DB']
    before {skip("Not supported for remote DB")}
  end

  include_context 'Msf::UIDriver'
  include_context 'Msf::DBManager'

  def web_vuln_xml
    %{
      <Request>GET /search.php?q=test HTTP/1.1\r\nHost: 192.168.200.142\r\n\r\n</Request>
      <Response>HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Results</body></html></Response>
    }
  end

  def other_vuln_xml
    %{<Request><![CDATA[Not available in the free trial]]></Request>}
  end

  def xml_block(interpolated_vuln)
    %{<?xml version="1.0"?>
<ScanGroup ExportedOn="26/04/2023, 00:33:40">
  <Scan>
    <Name><![CDATA[scan_name]]></Name>
    <ShortName><![CDATA[scan_short_name]]></ShortName>
    <StartURL><![CDATA[http://192.168.200.142]]></StartURL>
    <StartTime><![CDATA[26/04/2023, 00:27:04]]></StartTime>
    <FinishTime><![CDATA[26/04/2023, 00:32:06]]></FinishTime>
    <ScanTime><![CDATA[4 minutes, 57 seconds]]></ScanTime>
    <Aborted><![CDATA[True]]></Aborted>
    <Responsive><![CDATA[]]></Responsive>
    <Banner><![CDATA[]]></Banner>
    <Os><![CDATA[]]></Os>
    <WebServer><![CDATA[]]></WebServer>
    <Technologies>
      <![CDATA[]]>
    </Technologies>
    <Crawler StartUrl="http://192.168.200.142">
      <Cookies>

      </Cookies>
      <SiteFiles>
        <SiteFile id="1">
          <Name><![CDATA[http://192.168.200.142/]]></Name>
          <URL><![CDATA[/]]></URL>
          <FullURL><![CDATA[http://192.168.200.142/]]></FullURL>

        </SiteFile>
      </SiteFiles>
    </Crawler>
    <ReportItems>
      <ReportItem id="1" color="red">
        <Name><![CDATA[PHP-CGI remote code execution]]></Name>
        <ModuleName><![CDATA[Scripting (PHP_CGI_RCE_Force_Redirect.script)]]></ModuleName>
        <Details><![CDATA[Not available in the free trial]]></Details>
        <Affects><![CDATA[/]]></Affects>
        <Parameter><![CDATA[]]></Parameter>
        <AOP_SourceFile><![CDATA[]]></AOP_SourceFile>
        <AOP_SourceLine></AOP_SourceLine>
        <AOP_Additional><![CDATA[]]></AOP_Additional>
        <IsFalsePositive><![CDATA[]]></IsFalsePositive>
        <Severity><![CDATA[high]]></Severity>
        <Type><![CDATA[denialofservice]]></Type>
        <Impact><![CDATA[A remote unauthenticated attacker could obtain sensitive information, cause a denial of service condition or may be able to execute arbitrary code with the privileges of the web server.]]></Impact>
        <Description><![CDATA[PHP is a widely-used general-purpose scripting language that is especially suited for Web development and can be embedded into HTML. When PHP is used in a CGI-based setup (such as Apache's mod_cgid), the php-cgi receives a processed query string parameter as command line arguments which allows command-line switches, such as -s, -d or -c to be passed to the php-cgi binary, which can be exploited to disclose source code and obtain arbitrary code execution. <br/><br/>
An example of the -s command, allowing an attacker to view the source code of index.php is below:
<pre>
http://localhost/index.php?-s
</pre>
]]></Description>
        <DetailedInformation><![CDATA[]]></DetailedInformation>
        <Recommendation><![CDATA[An alternative is to configure your web server to not let these types of requests with query strings starting with a &quot;-&quot; and not containing a &quot;=&quot; through. Adding a rule like this should not break any sites. For Apache using mod_rewrite it would look like this: <br/><br/>
<code><pre>
         RewriteCond %{QUERY_STRING} ^(%2d|-)[^=]+$ [NC]
         RewriteRule ^(.*) $1? [L]
</pre></code>]]></Recommendation>
        <TechnicalDetails>
          #{interpolated_vuln}
        </TechnicalDetails>
        <CWEList>

          <CWE id="20"><![CDATA[CWE-20]]></CWE>

        </CWEList>
        <CVEList>

          <CVE id="1823" year="2012"><![CDATA[CVE-2012-1823]]></CVE>

          <CVE id="2311" year="2012"><![CDATA[CVE-2012-2311]]></CVE>

        </CVEList>
        <CVSS>
          <Descriptor><![CDATA[AV:N/AC:L/Au:N/C:P/I:P/A:P/E:F/RL:OF/RC:C]]></Descriptor>
          <Score><![CDATA[7.5]]></Score>
          <AV><![CDATA[Network_Accessible]]></AV>
          <AC><![CDATA[Low]]></AC>
          <Au><![CDATA[None]]></Au>
          <C><![CDATA[Partial]]></C>
          <I><![CDATA[Partial]]></I>
          <A><![CDATA[Partial]]></A>
          <E><![CDATA[]]></E>
          <RL><![CDATA[]]></RL>
          <RC><![CDATA[]]></RC>
        </CVSS>

        <References>

          <Reference>
            <Database><![CDATA[Eindbazen PHP-CGI advisory (CVE-2012-1823)]]></Database>
            <URL><![CDATA[http://eindbazen.net/2012/05/php-cgi-advisory-cve-2012-1823/]]></URL>
          </Reference>

          <Reference>
            <Database><![CDATA[CVE-2012-1823-mitigation]]></Database>
            <URL><![CDATA[http://eindbazen.net/wp-content/uploads/2012/05/CVE-2012-1823-mitigation.tar.gz]]></URL>
          </Reference>

          <Reference>
            <Database><![CDATA[PHP-CGI query string parameter vulnerability]]></Database>
            <URL><![CDATA[http://www.kb.cert.org/vuls/id/520827]]></URL>
          </Reference>

          <Reference>
            <Database><![CDATA[PHP 5.3.12 and PHP 5.4.2 Released!]]></Database>
            <URL><![CDATA[http://www.php.net/archive/2012.php#id2012-05-03-1]]></URL>
          </Reference>

        </References>
      </ReportItem>
    </ReportItems>
  </Scan>
</ScanGroup>}
  end

  let(:acunetix_web_vuln_report) do
    xml_block(web_vuln_xml)
  end

  let(:acunetix_other_vuln_report) do
    xml_block(other_vuln_xml)
  end

  let(:acunetix_args) {
    {
      # Only the workspace arg is necessary.
      # Others such as `options`, `filename` and `blacklist` are not necessary here.
      workspace: framework.db.workspace.name
    }
  }

  describe '#parse' do
    subject do
      doc = Rex::Parser::AcunetixDocument.new(acunetix_args, framework.db)
      ::Nokogiri::XML::SAX::Parser.new(doc)
    end

    context 'when importing a file containing a web vulnerability' do
      it 'should import a web vulnerability' do
        # Calling .parse here populates out `framework.db.workspace.web_vulns` and `vulns`. It does not return any value.
        subject.parse(acunetix_web_vuln_report)

        # After the fix, web vulnerabilities with request/response data should still be reported as web_vuln
        expect(framework.db.workspace.web_vulns.length).to be >= 1
        expect(framework.db.workspace.web_vulns.first.name).to eq('PHP-CGI remote code execution')
      end
    end

    context 'when importing a file containing a normal vulnerability' do
      it 'should import a normal vulnerability' do
        subject.parse(acunetix_other_vuln_report)

        expect(framework.db.workspace.vulns.length).to be >= 1
        expect(framework.db.workspace.vulns.first.name).to eq('PHP-CGI remote code execution')
      end
    end
  end
end

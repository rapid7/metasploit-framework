##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kerberos keytab utilities',
        'Description' => %q{
          Utilities for interacting with MIT keytab files, which can store the hashed passwords of one or
          more principals.

          Discovered keytab files can be used to generate Kerberos Ticket Granting Tickets, or bruteforced
          offline.

          Keytab files can be also useful for decrypting Kerberos traffic using Wireshark dissectors,
          including the krbtgt encrypted blobs if the AES password hash is used.
        },
        'Author' => [
          'alanfoster' # Metasploit Module
        ],
        'References' => [
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [],
          'SideEffects' => [],
          'Reliability' => [],
          'AKA' => []
        },
        'Actions' => [
          ['LIST', { 'Description' => 'List the entries in the keytab file' }],
          ['ADD', { 'Description' => 'Add a new entry to the keytab file' }],
        ],
        'DefaultAction' => 'LIST'
      )
    )

    supported_encryption_names = ['ALL']
    supported_encryption_names += Rex::Proto::Kerberos::Crypto::Encryption::SUPPORTED_ENCRYPTIONS
                              .map { |id| Rex::Proto::Kerberos::Crypto::Encryption.const_name(id) }

    register_options(
      [
        OptString.new('KEYTAB_FILE', [false, 'The keytab file to manipulate']),
        OptString.new('PRINCIPAL', [true, 'The kerberos principal name']),
        OptString.new('REALM', [true, 'The kerberos realm']),
        OptEnum.new('ENCTYPE', [true, 'The enctype to use. If a password is specified this can set to \'ALL\'', nil, supported_encryption_names]),
        OptString.new('KEY', [true, 'The key to use. If not specified, the key will be generated from th password']),

        OptString.new('PASSWORD', [true, 'The password name. If not specified, the hash will be used']),
        OptString.new('SALT', [false, 'The salt to use when creating a key from the password. If not specified, this will be generated from the principal name']),

        OptInt.new('KVNO', [true, 'The kerberos key version number', 0]),
        OptEnum.new('OUTPUT_FORMAT', [true, 'The output format to use for listing keytab entries', 'table', %w[csv table]]),
      ]
    )
  end

  def run
    if datastore['KEYTAB_FILE'].blank?
      fail_with(Failure::BadConfig, 'Invalid key tab file')
    end

    case action.name
    when 'ADD'
      add_keytab_entry
    when 'LIST'
      list_keytab_entries
    end
  end

  # Add keytab entries into the given keytab file. The keytab file will be created if it did not previously exist.
  def add_keytab_entry
    keytab_path = datastore['KEYTAB_FILE']

    if File.exist?(keytab_path)
      vprint_status('modifying existing keytab')
      keytab = Rex::Proto::Kerberos::KeyTab::KeyTab.read(File.binread(datastore['KEYTAB_FILE']))
    else
      vprint_status('creating new keytab')
      keytab = Rex::Proto::Kerberos::KeyTab::KeyTab.new
    end

    principal, realm = 'Administrator@DOMAIN.LOCAL'.split('@')
    if principal.blank? || realm.blank?
      fail_with(Failure::BadConfig, 'Principal missing realm')
    end

    components = principal.split('/')

    key_blocks = []
    if datastore['KEY'].present?
      fail_with(Failure::BadConfig, 'enctype ALL not supported when KEY is set') if datastore['ENCTYPE'] == 'ALL'

      key_blocks << {
        enctype: Rex::Proto::Kerberos::Crypto::Encryption.value_for(datastore['ENCTYPE']),
        data: [datastore['KEY']].pack('H*')
      }
    elsif datastore['PASSWORD'].present?
      password = datastore['PASSWORD']
      # For Active Directory environments this is upper case domain, with a case sensitive username
      salt = datastore['SALT'] || "#{realm}#{components[0]}"
      vprint_status("Using salt #{salt} - note the realm and principal can be case sensitive when targeting environments.")

      enctypes = datastore['ENCTYPE'] == 'ALL' \
                   ? Rex::Proto::Kerberos::Crypto::Encryption::SUPPORTED_ENCRYPTIONS
                   : [Rex::Proto::Kerberos::Crypto::Encryption.value_for(datastore['ENCTYPE'])]
      enctypes.each do |enctype|
        encryptor = Rex::Proto::Kerberos::Crypto::Encryption.from_etype(enctype)
        key_blocks << {
          enctype: enctype,
          data: encryptor.string_to_key(password, salt)
        }
      end
    else
      fail_with(Failure::BadConfig, 'KEY or PASSWORD required')
    end

    key_blocks.each do |key_block|
      entry = {
        realm: realm,
        components: components,
        name_type: Rex::Proto::Kerberos::Model::NameType::NT_PRINCIPAL,
        timestamp: Time.at(0),
        vno8: datastore['KVNO'],
        vno: datastore['KVNO'],
        key_block: key_block
      }
      keytab.key_entries << entry
    end

    # TODO: Confirm if we want to use store_loot here or not
    File.binwrite(keytab_path, keytab.to_binary_s)
    print_good "keytab entry added to #{keytab_path}"

    if datastore['VERBOSE']
      list_keytab_entries
    end
  end

  # List the keytab entries within the keytab file
  def list_keytab_entries
    if datastore['KEYTAB_FILE'].blank? || !File.exist?(datastore['KEYTAB_FILE'])
      fail_with(Failure::BadConfig, 'Invalid key tab file')
    end

    tbl = Rex::Text::Table.new(
      'Header' => 'Keytab entries',
      'Indent' => 1,
      'WordWrap' => false,
      'Columns' => %w[
        vno
        type
        principal
        hash
        date
      ]
    )

    keytab = File.binread(datastore['KEYTAB_FILE'])
    keytab = Rex::Proto::Kerberos::KeyTab::KeyTab.read(keytab)
    keytab.key_entries.each do |entry|
      key_block = entry.key_block
      tbl << [
        entry.vno,
        enctype_name(key_block.enctype),
        entry.principal,
        key_block.data.unpack1('H*'),
        entry.timestamp,
      ]
    end

    case datastore['OUTPUT_FORMAT']
    when 'table'
      print_line(tbl.to_s)
    when 'csv'
      print_line(tbl.to_csv)
    else
      print_line(tbl.to_s)
    end
  end

  # @param [Object] id
  # @see Rex::Proto::Kerberos::Crypto::Encryption
  def enctype_name(id)
    name = Rex::Proto::Kerberos::Crypto::Encryption.const_name(id)
    name ? "#{id} (#{name})" : id.to_s
  end
end

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
          Utilities for interacting with keytab files, which can store the hashed passwords of one or
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
          'Reliability' => []
        },
        'Actions' => [
          ['LIST', { 'Description' => 'List the entries in the keytab file' }],
          ['ADD', { 'Description' => 'Add a new entry to the keytab file' }],
        ],
        'DefaultAction' => 'LIST',
        'DefaultOptions' => {
          'VERBOSE' => true
        }
      )
    )

    supported_encryption_names = ['ALL']
    supported_encryption_names += Rex::Proto::Kerberos::Crypto::Encryption::SUPPORTED_ENCRYPTIONS
                                  .map { |id| Rex::Proto::Kerberos::Crypto::Encryption.const_name(id) }

    register_options(
      [
        OptString.new('KEYTAB_FILE', [true, 'The keytab file to manipulate']),
        OptString.new('PRINCIPAL', [false, 'The kerberos principal name']),
        OptString.new('REALM', [false, 'The kerberos realm']),
        OptEnum.new('ENCTYPE', [false, 'The enctype to use. If a password is specified this can set to \'ALL\'', supported_encryption_names[0], supported_encryption_names]),
        OptString.new('KEY', [false, 'The key to use. If not specified, the key will be generated from the password']),
        OptString.new('PASSWORD', [false, 'The password. If not specified, the KEY option will be used']),
        OptString.new('SALT', [false, 'The salt to use when creating a key from the password. If not specified, this will be generated from the principal name']),
        OptInt.new('KVNO', [true, 'The kerberos key version number', 1]),
        OptEnum.new('OUTPUT_FORMAT', [true, 'The output format to use for listing keytab entries', 'table', %w[csv table]]),
      ]
    )
  end

  def run
    if datastore['KEYTAB_FILE'].blank?
      fail_with(Failure::BadConfig, 'KEYTAB_FILE must be set to a non-empty string')
    end

    case action.name
    when 'LIST'
      list_keytab_entries
    when 'ADD'
      add_keytab_entry
    end
  end

  # Add keytab entries into the given keytab file. The keytab file will be created if it did not previously exist.
  def add_keytab_entry
    keytab_path = datastore['KEYTAB_FILE']

    if File.exist?(keytab_path)
      keytab = Rex::Proto::Kerberos::Keytab::Keytab.read(File.binread(datastore['KEYTAB_FILE']))
    else
      keytab = Rex::Proto::Kerberos::Keytab::Keytab.new
    end

    principal = datastore['PRINCIPAL']
    fail_with(Failure::BadConfig, 'PRINCIPAL must be set to a non-empty string') if principal.blank?

    realm = datastore['REALM']
    fail_with(Failure::BadConfig, 'REALM must be set to a non-empty string') if realm.blank?

    if /[[:lower:]]/.match(realm)
      print_warning("REALM option has lowercase letters present - this may not work as expected for Window's Active Directory environments which uses a uppercase domain")
    end

    components = principal.split('/')
    keyblocks = []
    if datastore['KEY'].present?
      fail_with(Failure::BadConfig, 'enctype ALL not supported when KEY is set') if datastore['ENCTYPE'] == 'ALL'

      keyblocks << {
        enctype: Rex::Proto::Kerberos::Crypto::Encryption.value_for(datastore['ENCTYPE']),
        data: [datastore['KEY']].pack('H*')
      }
    elsif datastore['PASSWORD'].present?
      password = datastore['PASSWORD']
      salt = datastore['SALT']
      if salt.blank?
        salt = "#{realm}#{components[0]}"
        vprint_status("Generating key with salt: #{salt}. The SALT option can be set manually")
      end

      if datastore['ENCTYPE'] == 'ALL'
        enctypes = Rex::Proto::Kerberos::Crypto::Encryption::SUPPORTED_ENCRYPTIONS
      else
        enctypes = [Rex::Proto::Kerberos::Crypto::Encryption.value_for(datastore['ENCTYPE'])]
      end

      enctypes.each do |enctype|
        encryptor = Rex::Proto::Kerberos::Crypto::Encryption.from_etype(enctype)
        keyblocks << {
          enctype: enctype,
          data: encryptor.string_to_key(password, salt)
        }
      end
    else
      fail_with(Failure::BadConfig, 'KEY or PASSWORD required to add a new entry')
    end

    keyblocks.each do |keyblock|
      entry = {
        realm: realm,
        components: components,
        name_type: Rex::Proto::Kerberos::Model::NameType::NT_PRINCIPAL,
        timestamp: Time.at(0).utc,
        vno8: datastore['KVNO'],
        vno: datastore['KVNO'],
        keyblock: keyblock
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
        kvno
        type
        principal
        hash
        date
      ]
    )

    keytab = File.binread(datastore['KEYTAB_FILE'])
    keytab = Rex::Proto::Kerberos::Keytab::Keytab.read(keytab)
    keytab.key_entries.each do |entry|
      keyblock = entry.keyblock
      tbl << [
        entry.vno,
        enctype_name(keyblock.enctype),
        entry.principal,
        keyblock.data.unpack1('H*'),
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
    name ? "#{id.to_s.ljust(2)} (#{name})" : id.to_s
  end
end

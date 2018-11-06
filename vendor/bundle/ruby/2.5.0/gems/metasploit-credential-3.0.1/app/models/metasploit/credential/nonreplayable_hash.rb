# A {Metasploit::Credential::PasswordHash password hash} that cannot be replayed to authenticate to other services.
# Contrast with {Metasploit::Credential::ReplayableHash}.  {#data} is any password hash, such as those recovered from
# `/etc/passwd` or `/etc/shadow`.
class Metasploit::Credential::NonreplayableHash < Metasploit::Credential::PasswordHash

  #
  # Constants
  #

  # The names of John the Ripper supported formats, from the "jumbo" edition.
  # Listed in the format section of the output of +john --help+ on the CLI
  # Current as of 2014-06-12
  VALID_JTR_FORMATS = %w(afs bf bf-opencl bfegg bsdi crc32 des django dmd5 dominosec dragonfly3-32 dragonfly3-64
                         dragonfly4-32 dragonfly4-64 drupal7 dummy dynamic_n epi episerver gost hdaa hmac-md5 hmac-sha1
                         hmac-sha224 hmac-sha256 hmac-sha384 hmac-sha512 hmailserver ipb2 keepass keychain krb4 krb5 lm
                         lotus5 md4-gen md5 md5crypt-opencl md5ns mediawiki mscash mscash2 mscash2-opencl mschapv2
                         mskrb5 mssql mssql05 mysql mysql-sha1 mysql-sha1-opencl nethalflm netlm netlmv2 netntlm
                         netntlmv2 nsldap nt nt-opencl nt2 odf office oracle oracle11 osc pdf phpass phpass-opencl phps
                         pix-md5 pkzip po pwsafe pwsafe-opencl racf rar raw-md4 raw-md4-opencl raw-md5 raw-md5-opencl
                         raw-md5u raw-sha raw-sha1 raw-sha1-linkedin raw-sha1-ng raw-sha1-opencl raw-sha224 raw-sha256
                         raw-sha384 raw-sha512 raw-sha512-opencl salted-sha1 sapb sapg sha1-gen sha256crypt sha512crypt
                         sha512crypt-opencl sip ssh ssha-opencl sybasease trip vnc wbb3 wpapsk wpapsk-opencl xsha
                         xsha512 xsha512-opencl zip)

  #
  # Attributes
  #

  # @!attribute data
  #   Password hash that cannot be replayable for authenticating to other services.
  #
  #   @return [String]

  Metasploit::Concern.run(self)
end

# Release Notes

##v1.61.2

* Add new root key

## v1.61.1

* Add Addressable as a gem runtime dependency

## v1.61.0

* Add URI, CDS and CDNSKEY records
* Supply port to DNS.new as optiona parameter
* Supply timeout to zone transfer connect
* Fix multi-line strings
* Try absolute name as candidate in DNS even if not dot supplied
* Do not try to generate candidates if no domain is given
* Handle new OpenSSL interface as well as old
* Handle new DSA interface
* fix encode error select thread issue
* handle encoding errors
* add punycode support
* Make sure dnssec is enabled in verifier and also in digroot demo
* Other minor fixes and changes to test code and infrastructure

## v1.60.2

* Fix deletion of TXT records with spaces in dynamic updates (thanks Sean Dilda)
* Fix use of non-default ports in Dnsruby::Resolver (thanks Thomas Morgan)
* Fix NAPTR encoding for null rdata dynamic update packets
* Fix CAA resource record encoding
* Avoid changing ruby global thread abort behavior (thanks Brent Cook)

## v1.60.1

* DNSSEC validation switched OFF by default (but can still be switched on)
* Add APL RR support (thanks Manabu Sonoda)
* Various test fixes (thanks Keith Bennett)
* 'include' issues fixed (thanks Keith Bennett!)
* Fixnum replacement (thanks Keith Bennett)
* Zone transfer fixes (thanks Manabu Sonoda)
* Name decoding fix
* MX record passing error now raised
* CAA RR support (thanks Richard Luther)
* TLSA RR support (thanks Manabu Sonoda)


## v1.60.0

* TCP multi-packet support fixed
* Response 'Message' now included with exception.
* Docs added
* CNAME dynamic update fix

## v1.59.3

* Output TXT record multiple strings correctly
* NONE class encoding fix
* only add name labels if there are any

## v1.59.2

* Timeout error fix

## v1.59.1

* Support for HMAC SHA512 TSIG keys
* Fix TCP pipelining tests
* IDN encoding error returned as Dnsruby::OtherResolvError

## v1.59.0

* Add LICENSE file
* Add Cache max_size (gihub issue 64)
* Disable caching for SOA lookups in demo check_soa.rb
* Fix for invalid nameserver in config
* Fix encoding for OPT data (thanks Craig Despeaux)
* Various test system fixes
* OPT fixes
* DNSSEC verification failure handling wrt lack of DS chain
* DNSSEC validation policy name constants
* Fix for BOGUS DLV chains
* demo upgrades
* Resolver hints improvements 


## v1.58.0

* Add TCP pipelining (reusing a single TCP connection for multiple requests).
* Enhance zone reading, including reading data from a string.
* Add add_answer! method for adding duplicate answers, as needed for an AXFR response.
* Add support for GPOS and NXT resource records.
* Test cleanup, including removal of use of Nominet servers, soak_test cleanup.
* Refactorings: MessageDecoder, Resolv, Resolver (part).
* Fix zone reader adding unwanted dot to relative hostnames being converted to absolute.
* Fix default access for tsig options in Resolver.
* Fix ZoneTransfer not to use deprecated SingleResolver.
* Fix Resolver bug in parameter to create_tsig_options.
* Fix tests to always use working copy and not gem.


## v1.57.0

* Add query_raw method as alias for send_plain_message, with option to raise or return error.
* Fixed a bug in RR hash calculation where TTL should have been ignored but wasn't.
* Add support for (obsolete) GPOS resource record type.
* Tweak Travis CI configuration.
* Fix zone reader for case where a line contains whitespace preceding a comment.
* Add post install message.
* Improve README.
* Moved content of NEWS to RELEASE_NOTES.md.
* Use git ls-files now to determine files for inclusion in gem.


## v1.56.0

* Drop support for Ruby 1.8, using lambda -> and hash 'key: value' notations.
* First release since the move from Rubyforge to Github (https://github.com/alexdalitz/dnsruby).
* Add EDNS client subnet support.
* Relocate CodeMapper subclasses, Resolv, RR, and RRSet classes.
* Add Travis CI and coveralls integration.
* Improve Google IPV6 support.
* Convert some file names to snake case.
* Remove trailing whitespace from lines, and ensure that comments have space between '#' and text.
* Restore test success when running under JRuby.
* Disabled attempt to connect to Nominet servers, which are no longer available.
* Convert from test/unit to minitest/autorun to support Ruby 2.1+.
* Remove setup.rb.
* Other minor refactoring and improvements to production code, test code, and documentation.


## v1.53

* Validation routine fixes
* Ruby 1.9 fixes
* Recursor fixes
* IPv4 Regex fixes
* Fixes for A/PTR lookups with IP-like domain name
* TXT and SSHFP processing fixes
* Default retry parameters in Resolver more sensible


## v1.48

* Fixed deadlock/performance issue seen on some platforms
* DNSSEC validation now disabled by default
* Signed root DS record can be added to validator
* ITAR support removed
* multi-line DS/RRSIG reading bug fixed (thanks Marco Davids!)
* DS algorithms of more than one digit can now be read from string
* LOC records now parsed correctly
* HINFO records now parsed correctly


## v1.42

* Complicated TXT and NAPTR records now handled correctly
* ZoneReader now handles odd escape characters correctly
* Warns when immediate timeout occurs because no nameservers are configured
* Easy hmac-sha1/256 options to Resolver#tsig=
* ZoneReader fixed for "IN CNAME @" notations
* ZoneReader supports wildcards
* Dnsruby.version method added - currently returns 1.42


## v1.41

* RFC3597 unknown classes (e.g. CLASS32) now handled correctly
    in RRSIGs
* Resolver#do_caching flag added for Resolver-level caching
* DNSKEY#key_tag now cached - only recalculated when key data
    changes
* Bugfix where Resolver would not time queries out if no 
    nameservers were configured
* Recursor now performs A and AAAA queries in parallel
* Fix for zero length salt
* Fixing priming for signed root
* Fixes for DLV verification
* Other minor fixes


## v1.40

* Zone file reading support added (Dnsruby::ZoneReader)
* Name and Label speed-ups
* CodeMapper speed-ups
* DHCID RR added
* LOC presentation format parsing fixed
* KX RR added
* Quotations now allowed in text representation for ISDN, X25 and HINFO
* AFSDB from_string fixes
* Fixing CERT types and from_string
* CERT now allows algorithm 0
* Fix for DS record comparison
* HIP RR added
* Minor bug fixes
* IPSECKEY RR added
* Clients can now manipulate Name::Labels


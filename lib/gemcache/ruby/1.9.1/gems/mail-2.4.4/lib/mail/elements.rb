module Mail
  autoload :Address, 'mail/elements/address'
  autoload :AddressList, 'mail/elements/address_list'
  autoload :ContentDispositionElement, 'mail/elements/content_disposition_element'
  autoload :ContentLocationElement, 'mail/elements/content_location_element'
  autoload :ContentTransferEncodingElement, 'mail/elements/content_transfer_encoding_element'
  autoload :ContentTypeElement, 'mail/elements/content_type_element'
  autoload :DateTimeElement, 'mail/elements/date_time_element'
  autoload :EnvelopeFromElement, 'mail/elements/envelope_from_element'
  autoload :MessageIdsElement, 'mail/elements/message_ids_element'
  autoload :MimeVersionElement, 'mail/elements/mime_version_element'
  autoload :PhraseList, 'mail/elements/phrase_list'
  autoload :ReceivedElement, 'mail/elements/received_element'
end

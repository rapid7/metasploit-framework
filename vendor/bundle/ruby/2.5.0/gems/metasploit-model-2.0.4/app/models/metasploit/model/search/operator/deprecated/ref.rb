# Translates `ref:<value>` to union of `authorities.abbreviation:<value>`, `references.designation:<value>`, and
# `references.designation:<value>`.
class Metasploit::Model::Search::Operator::Deprecated::Ref < Metasploit::Model::Search::Operator::Group::Union
  # Array of `authorities.abbreviation:<formatted_value>`, `references.designation:<formatted_value>`, and
  # `references.url:<formatted_value>`.  If `formatted_value` contains a '-' then the portion of `formatted_value`
  # before '-' is treated is passed to `authorities.abbreviation` and the portion of `formatted_value` after '-' is
  # treated is passed to `references.designation`.  If the portion of `formatted_value` before the '-'
  # case-insensitively matches 'URL', then `authorities.abbreviation` and `references.designation` is not used and the
  # portion of `formatted_value` after the '-' is passed to `references.url`.  If any portion of the parsed
  # `formatted_value` is blank, then the corresponding child operation will not be in the returned Array.
  #
  # @param formatted_value [String] value parsed from formatted operation.
  # @return [Array<Metasploit::Model::Search::Operation::Base>]
  def children(formatted_value)
    if formatted_value.include? '-'
      head, tail = formatted_value.split('-', 2)

      if head.casecmp('URL') == 0
        # URL is not a valid abbreviation
        abbreviation = nil
        designation = nil
        url = tail
      else
        abbreviation = head
        designation = tail
        url = nil
      end
    else
      abbreviation = formatted_value
      designation = formatted_value
      url = formatted_value
    end

    operations = []

    unless abbreviation.blank?
      operations << operator('authorities.abbreviation').operate_on(abbreviation)
    end

    unless designation.blank?
      operations << operator('references.designation').operate_on(designation)
    end

    unless url.blank?
      operations << operator('references.url').operate_on(url)
    end

    operations
  end
end
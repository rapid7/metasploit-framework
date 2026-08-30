module Rex::Proto::Gss::Asn1
  #
  # GSS has some "pseudo-asn1" to wrap up tokens. This function parses that wrapping, extracts
  # the mechanism specified, and returns it and the token following it
  def unwrap_pseudo_asn1(token)
    start_of_token = nil
    mech_id = nil
    # This bit is pseudo-ASN1 - we parse up until the OID, then take note of where we got up 
    # to, and continue parsing from there.
    OpenSSL::ASN1.traverse(token) do | depth, offset, header_len, length, constructed, tag_class, tag|
      component = token[offset, header_len+length]
      if depth == 1 && tag_class == :UNIVERSAL && tag == 6
        mech_id = OpenSSL::ASN1.decode(component)
        start_of_token = offset+header_len+length
        break
      end
    end

    [mech_id, token[start_of_token, token.length - start_of_token]]
  end

  def wrap_pseudo_asn1(mech_id, token)
    OpenSSL::ASN1::ASN1Data.new(
      [
        mech_id,
        token
      ],
      0,
      :APPLICATION
    ).to_der
  end
end

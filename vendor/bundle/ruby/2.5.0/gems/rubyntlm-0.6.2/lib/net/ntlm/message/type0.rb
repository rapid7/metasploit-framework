module Net
  module NTLM
    class Message

      # sub class definitions
      class Type0 < Message
        string        :sign,      {:size => 8, :value => SSP_SIGN}
        int32LE       :type,      {:value => 0}
      end


    end
  end
end



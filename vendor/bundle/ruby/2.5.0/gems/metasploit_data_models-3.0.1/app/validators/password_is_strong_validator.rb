# Validates that
class PasswordIsStrongValidator < ActiveModel::EachValidator
  #
  # CONSTANTS
  #

  # Known passwords that should NOT be allowed and should be considered weak.
  COMMON_PASSWORDS = %w{
      password pass root admin metasploit
      msf 123456 qwerty abc123 letmein monkey link182 demo
      changeme test1234 rapid7
    }

  # Special characters that are considered to strength passwords and are required once in a strong password.
  SPECIAL_CHARS = %q{!@"#$%&'()*+,-./:;<=>?[\\]^_`{|}~ }

  # Validates that the `attribute`'s `value` on `record` contains letters, numbers, and at least one special character
  # without containing the `record.username`, any {COMMON_PASSWORDS} or repetition.
  def validate_each(record, attribute, value)
    return if value.blank?

    if is_simple?(value)
      record.errors[attribute] << "must contain letters, numbers, and at least one special character"
    end

    if contains_username?(record.username, value)
      record.errors[attribute] << "must not contain the username"
    end

    if is_common_password?(value)
      record.errors[attribute] << "must not be a common password"
    end

    if contains_repetition?(value)
      record.errors[attribute] << "must not be a predictable sequence of characters"
    end
  end

  private

  def is_simple?(password)
    not (password =~ /[A-Za-z]/ and password =~ /[0-9]/ and password =~ /[#{Regexp.escape(SPECIAL_CHARS)}]/)
  end

  def contains_username?(username, password)
    !!(password =~ /#{username}/i)
  end

  def is_common_password?(password)
    COMMON_PASSWORDS.each do |pw|
      common_pw = [pw] # pw + "!", pw + "1", pw + "12", pw + "123", pw + "1234"]
      common_pw += mutate_pass(pw)
      common_pw.each do |common_pass|
        if password.downcase =~ /#{common_pass}[\d!]*/
          return true
        end
      end
    end
    false
  end

  def mutate_pass(password)
    mutations = {
        'a' => '@',
        'o' => '0',
        'e' => '3',
        's' => '$',
        't' => '7',
        'l' => '1'
    }

    iterations = mutations.keys.dup
    results = []

    # Find PowerSet of all possible mutation combinations
    iterations = iterations.inject([[]]){|c,y|r=[];c.each{|i|r<<i;r<<i+[y]};r}

    # Iterate through combinations to create each possible mutation
    iterations.each do |iteration|
      next if iteration.flatten.empty?
      first = iteration.shift
      intermediate = password.gsub(/#{first}/i, mutations[first])
      iteration.each do |mutator|
        next unless mutator.kind_of? String
        intermediate.gsub!(/#{mutator}/i, mutations[mutator])
      end
      results << intermediate
    end

    return results
  end



  def contains_repetition?(password)
    # Password repetition (quite basic) -- no "aaaaaa" or "ababab" or "abcabc" or
    # "abcdabcd" (but note that the user can use "aaaaaab" or something).

    if password.scan(/./).uniq.size < 2
      return true
    end

    if (password.size % 2 == 0) and (password.scan(/../).uniq.size < 2)
      return true
    end

    if (password.size % 3 == 0) and (password.scan(/.../).uniq.size < 2)
      return true
    end

    if (password.size % 4 == 0) and (password.scan(/..../).uniq.size < 2)
      return true
    end

    false
  end
end

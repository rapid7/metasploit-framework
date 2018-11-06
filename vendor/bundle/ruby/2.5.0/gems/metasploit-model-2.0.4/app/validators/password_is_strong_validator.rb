# Validates that the password is strong.
class PasswordIsStrongValidator < ActiveModel::EachValidator
  #
  # CONSTANTS
  #

  # Password that are used too often and will be easily guessed.
  COMMON_PASSWORDS = %w{
			password pass root admin metasploit
			msf 123456 qwerty abc123 letmein monkey link182 demo
			changeme test1234 rapid7
		}

  # Validates that `value` is a strong password.  A password is strong if it meets the following rules:
  # * SHOULD contain at least one letter.
  # * SHOULD contain at least one digit.
  # * SHOULD contain at least one special character.
  # * SHOULD NOT contain `record.username` (case-insensitive).
  # * SHOULD NOT be in {COMMON_PASSWORDS}.
  # * SHOULD NOT repetitions.
  #
  # @param record [#errors, #username, ActiveRecord::Base] ActiveModel or ActiveRecord that supports #username method.
  # @param attribute [Symbol] password attribute name.
  # @param value [String] a password.
  # @return [void]
  def validate_each(record, attribute, value)
    return if value.blank?

    if is_simple?(value)
      record.errors[attribute] << 'must contain letters, numbers, and at least one special character'
    end

    if contains_username?(record.username, value)
      record.errors[attribute] << 'must not contain the username'
    end

    if is_common_password?(value)
      record.errors[attribute] << 'must not be a common password'
    end

    if contains_repetition?(value)
      record.errors[attribute] << 'must not be a predictable sequence of characters'
    end
  end

  private

  # Password repetition (quite basic) -- no "aaaaaa" or "ababab" or "abcabc" or
  # "abcdabcd" (but note that the user can use "aaaaaab" or something).
  #
  # @param password [String]
  # @return [Boolean]
  def contains_repetition?(password)
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

  # Whether username is in password (case-insensitively).
  #
  # @return [false] if `password` is blank.
  # @return [false] if `username` is blank.
  # @return [false] unless `username` is in `password`.
  # @return [true] if `username` is in `password`.
  def contains_username?(username, password)
    contains = false

    unless password.blank? or username.blank?
      escaped_username = Regexp.escape(username)
      username_regexp = Regexp.new(escaped_username, Regexp::IGNORECASE)

      if username_regexp.match(password)
        contains = true
      end
    end

    contains
  end

  # Whether `password` is in {COMMON_PASSWORDS} or a simple variation of a password in {COMMON_PASSWORDS}.
  #
  # @param password [String]
  # @return [Boolean]
  def is_common_password?(password)
    COMMON_PASSWORDS.each do |pw|
      common_pw = [pw, pw + "!", pw + "1", pw + "12", pw + "123", pw + "1234"]
      if common_pw.include?(password.downcase)
        return true
      end
    end
    false
  end

  # Returns whether the password is simple.
  #
  # @return [false] if password contains a letter, digit and special character.
  # @return [true] otherwise
  def is_simple?(password)
    not (password =~ /[A-Za-z]/ and password =~ /[0-9]/ and password =~ /[\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x3a\x3b\x3c\x3d\x3e\x3f\x5b\x5c\x5d\x5e\x5f\x60\x7b\x7c\x7d\x7e]/)
  end
end
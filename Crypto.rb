require 'openssl'

# Adapted from http://www.brentsowers.com/2007/12/cipher-encryption-and-decryption-in-ruby.html
module Crypto
  def Crypto.encrypt(data, key, iv, mode)
    cipher = OpenSSL::Cipher::Cipher.new(mode)
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv if iv != nil
    return cipher.update(data) + cipher.final
  end

  def Crypto.decrypt(encrypted_data, key, iv, mode)
    cipher = OpenSSL::Cipher::Cipher.new(mode)
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv if iv != nil
    return cipher.update(encrypted_data) + cipher.final
  end
end

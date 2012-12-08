require 'openssl'

# Adapted from http://www.brentsowers.com/2007/12/aes-encryption-and-decryption-in-ruby.html
module AES
  BLOCKSIZE = 128 / 8

  def AES.encrypt(data, key, iv, mode)
    aes = OpenSSL::Cipher::Cipher.new(mode)
    aes.encrypt
    aes.key = key
    aes.iv = iv if iv != nil
    return aes.update(data) + aes.final
  end

  def AES.decrypt(encrypted_data, key, iv, mode)
    aes = OpenSSL::Cipher::Cipher.new(mode)
    aes.decrypt
    aes.key = key
    aes.iv = iv if iv != nil
    return aes.update(encrypted_data) + aes.final
  end
end

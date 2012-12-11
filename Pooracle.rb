require 'Util'

class Pooracle
  attr_accessor :verbose

  def initialize(mod)
    @module = mod
    @verbose = false
  end

  def do_block(num, block, previous, character = nil, blockprime = nil)
    # Initialized the blockprime variable to all zeroes if it's not set.
    # Interestingly, it doesn't actually matter how it's initialized, all
    # that matters is the length
    if(blockprime.nil?)
      blockprime = "\0" * @module.blocksize
    end

    # Default to the last character if none was passed
    if(character.nil?)
      character = @module.blocksize - 1
    end

    # When character is below 0, we've arrived at the beginning of the string
    if(character < 0)
      return ''
    end

    # Try every value for the current character
    0.upto(255) do |i|
      # Update the current character of blockprime
      blockprime[character] = i.chr

      # This line is the magic secret sauce. It attempts to decrypt the current
      # block using blockprime as the IV. If this is successful, then it means
      # that the padding is correct in the decrypted version
      result = @module.attempt_decrypt(blockprime, block)
      if(result)
        # Save calculating this multiple times
        expected_padding = @module.blocksize - character

        # The current plaintext character is the xor of:
        # 1. Our fake block's character (since it's XORed by that value in CBC)
        # 2. The expected padding value, because that's what the oracle thought it was
        # 3. The value of this character in the previous block, since that's
        #    what it had been XORed with in the original encryption (I originally
        #    screwed this one up!)
        plaintext_char = Util.ord(blockprime[character]) ^ expected_padding ^ Util.ord(previous[character])

        # Update @output_state and print it (purely for output)
        @output_state[((num - 1) * @module.blocksize) + character] = plaintext_char.chr
        if(@verbose)
          puts(">> \"#{Util.strclean(@output_state)}\"")
        end

        # Create the blockprime that's going to be used for the next level.
        # Basically, take the last 'n' characters of blockprime and set their
        # padding to the next padding value. I'd like to find a better way to
        # do this...
        new_blockprime = blockprime.clone
        (@module.blocksize - 1).step(character, -1) do |j|
          new_blockprime[j] = (Util.ord(new_blockprime[j]) ^ expected_padding ^ (expected_padding + 1)).chr
        end

        # Recursively do the next block. The reason for recursion is that it
        # makes it easy to resume if it turns out we got unlucky and the second
        # last character just happened to decrypt to \x02, meaning that setting
        # the last character to \x02 will be valid padding even when we expect
        # \x01
        chr = do_block(num, block, previous, character - 1, new_blockprime)
        if(!chr.nil?)
          return plaintext_char.chr + chr
        end
      end
    end

    puts("Couldn't find a proper padding! :(")
    return nil
  end

  def decrypt
    # Get the IV, defaulting to a NULL IV if we don't have one
    iv = @module.iv
    if(iv.nil?)
      iv = "\x00" * @module.blocksize
    end

    # Create the @output_state variable, which will be purely for output
    @output_state = '?' * @module.data.length

    # Add the IV to the start of the encrypted string (for simplicity)
    data  = iv + @module.data
    blockcount = data.length / @module.blocksize

    # Validate the blocksize
    if(data.length % @module.blocksize != 0)
      puts("Encrypted data isn't a multiple of the blocksize! Is this a block cipher?")
    end

    # Tell the user what's going on
    if(@verbose)
      puts("> Starting Pooracle decrypter with module #{@module.class::NAME}")
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
      new_result = do_block(i, blocks[i], blocks[i - 1])
      if(new_result.nil?)
        return nil
      end
      result = new_result.reverse + result
    end

    # Validate and remove the padding
    pad_bytes = result[result.length - 1]
    if(result[result.length - Util.ord(pad_bytes), result.length - 1] != pad_bytes * Util.ord(pad_bytes))
      return nil
    end
    result = result[0, result.length - Util.ord(pad_bytes)]

    return result
  end
end

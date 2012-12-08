require 'TestModule'

class Pooracle
  def initialize(mod)
    @module = mod
  end

  def do_block(block, lastblock, character = nil, fakeblock = nil)
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

    # Try every value for the current character
    0.upto(255) do |i|
      # Set the current character to the new value
      fakeblock[character] = i.chr

      # Attempt to decrypt our fake block and the real block
      result = @module.attempt_decrypt(fakeblock, block)
      if(result)
#        puts("Character: #{character}")
#        puts("Fakeblock: #{fakeblock.unpack("H*")} (#{fakeblock.length} bytes)")
#        puts("Lastblock: #{lastblock.unpack("H*")} (#{lastblock.length} bytes)")
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

  def decrypt
    # Get the IV, defaulting to a NULL IV if we don't have one
    iv = @module.iv
    if(iv.nil?)
      iv = "\x00" * @module.blocksize
    end

    # Add the IV to the start of the encrypted string (for simplicity)
    data  = iv + @module.data
    blockcount = data.length / @module.blocksize

    # Validate the blocksize
    if(data.length % @module.blocksize != 0)
      puts("Encrypted data isn't a multiple of the blocksize! Is this a block cipher?")
    end

    # Tell the user what's going on
    puts("> Starting Pooracle decrypter with module #{@module.class::NAME}")
    puts(">> Encrypted length: %d" % data.length)
    puts(">> Blocksize: %d" % @module.blocksize)
    puts(">> %d blocks:" % blockcount)

    blocks = data.unpack("a#{@module.blocksize}" * blockcount)
    i = 0
    blocks.each do |b|
      i = i + 1
      puts(">>> Block #{i}: #{b.unpack("H*")}")
    end

    # Decrypt all the blocks - from the last to the first (after the IV)
    result = ''
    (blocks.size - 1).step(1, -1) do |i|
      result = do_block(blocks[i], blocks[i - 1]).reverse + result
    end

    # Validate and remove the padding
    pad_bytes = result[result.length - 1]
    if(result[result.length - pad_bytes.ord, result.length - 1] != pad_bytes * pad_bytes.ord)
      return nil
    end
    result = result[0, result.length - pad_bytes.ord]

    return result
  end
end

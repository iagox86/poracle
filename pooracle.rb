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
        puts("Character: #{character}")
        puts("Fakeblock: #{fakeblock.unpack("H*")} (#{fakeblock.length} bytes)")
        puts("Lastblock: #{lastblock.unpack("H*")} (#{lastblock.length} bytes)")
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
    encrypted  = @module.iv + @module.get_encrypted_string()
    blocksize  = @module.blocksize
    blockcount = encrypted.length / blocksize

    if(encrypted.length % @module.blocksize != 0)
      puts("Encrypted data isn't a multiple of the blocksize! Is this a block cipher?")
    end

    puts("Encrypted length: %d" % encrypted.length)
    puts("Blocksize: %d" % blocksize)
    puts("Expected: %d blocks..." % blockcount)

    blocks = encrypted.unpack("a#{blocksize}" * blockcount)
    blocks.each do |b|
      puts(b.unpack("H*"))
    end

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

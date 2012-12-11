##
# LocaltestModule.rb
# Created: December 10, 2012
# By: Ron Bowes
#
# A very simple application that's vulnerable to a padding oracle
# attack. It's initialized with data and a mode, and the decrypt()
# function will try to decrypt the given data with the given key.
##

require 'openssl'

class LocalTestModule
  attr_reader :iv, :data, :blocksize

  NAME = "LocalTestModule(tm)"

  def initialize(mode, data, key = nil, iv = nil, verbose = false, delay = 0)
    # Save these variables
    @mode = mode
    @verbose = verbose
    @delay = delay

    # Create the cipher
    c = OpenSSL::Cipher::Cipher.new(mode)

    # Set up the required variables
    @blocksize = c.block_size
    @key = key.nil? ? (1..c.key_len).map{rand(255).chr}.join : key
    @iv  = iv.nil?  ? (1..c.iv_len).map{rand(255).chr}.join  : iv

    # Set up the cipher
    c.encrypt
    c.key = @key
    c.iv  = @iv

    @data = c.update(data) + c.final

    if(verbose)
      puts()
      puts("-" * 80)
      puts("Generated test data: #{data}")
      puts("-" * 80)
      puts("mode: #{mode}")
      puts("key:  #{@key.unpack("H*")}")
      puts("iv:   #{@iv.unpack("H*")}")
      puts("enc:  #{@data.unpack("H*")}")
      puts("-" * 80)
    end
  end

  # TODO: Make this a single argument
  def attempt_decrypt(data)
    begin
      if(@delay > 0)
        sleep(@delay)
      end

      c = OpenSSL::Cipher::Cipher.new(@mode)
      c.decrypt
      c.key = @key
      c.update(data) + c.final

      return true
    rescue # TODO: Be more specific
      return false
    end
  end
end


require 'Crypto'

class LocalTestModule
  attr_reader :iv, :blocksize, :data
  attr_accessor :verbose, :delay

  NAME = "LocalTestModule(tm)"

  def initialize()
    @verbose = false
    @delay   = 0
  end

  def des_from_data(data, key = nil, iv = nil)
    @blocksize = 64 / 8
    @key = key.nil? ? (1..8).map{rand(255).chr}.join : key
    @iv  = iv.nil?  ? (1..8).map{rand(255).chr}.join : iv
    @mode = "DES-CBC"
    @data = Crypto.encrypt(data, @key, @iv, @mode)

    if(verbose)
      puts()
      puts("-" * 80)
      puts("Generated test data: #{data}")
      puts("-" * 80)
      puts("key: #{@key.unpack("H*")}")
      puts("iv:  #{@iv.unpack("H*")}")
      puts("enc: #{@data.unpack("H*")}")
      puts("-" * 80)
    end
  end

  def aes_128_from_data(data, key = nil, iv = nil)
    @blocksize = 128 / 8
    @key = key.nil? ? (1..16).map{rand(255).chr}.join : key
    @iv  = iv.nil?  ? (1..16).map{rand(255).chr}.join : iv
    @mode = "AES-128-CBC"
    @data = Crypto.encrypt(data, @key, @iv, @mode)

    if(verbose)
      puts()
      puts("-" * 80)
      puts("Generated test data: #{data}")
      puts("-" * 80)
      puts("key: #{@key.unpack("H*")}")
      puts("iv:  #{@iv.unpack("H*")}")
      puts("enc: #{@data.unpack("H*")}")
      puts("-" * 80)
    end
  end

  def aes_128_from_enc(encrypted_data, key = nil, iv = nil)
    @blocksize = 128 / 8
    @key = key.nil? ? (1..16).map{rand(255).chr}.join : key
    @iv  = iv.nil?  ? (1..16).map{rand(255).chr}.join : iv
    @mode = "AES-128-CBC"
    @data = encrypted_data

    if(verbose)
      puts()
      puts("-" * 80)
      puts("Using pre-set data...")
      puts("-" * 80)
      puts("key: #{@key.unpack("H*")}")
      puts("iv:  #{@iv.unpack("H*")}")
      puts("enc: #{@data.unpack("H*")}")
      puts("-" * 80)
    end
  end

  def aes_192_from_data(data, key = nil, iv = nil)
    @blocksize = 128 / 8
    @key = key.nil? ? (1..24).map{rand(255).chr}.join : key
    @iv  = iv.nil?  ? (1..16).map{rand(255).chr}.join : iv
    @mode = "AES-192-CBC"
    @data = Crypto.encrypt(data, @key, @iv, @mode)

    if(verbose)
      puts()
      puts("-" * 80)
      puts("Generated test data: #{data}")
      puts("-" * 80)
      puts("key: #{@key.unpack("H*")}")
      puts("iv:  #{@iv.unpack("H*")}")
      puts("enc: #{@data.unpack("H*")}")
      puts("-" * 80)
    end
  end

  def aes_256_from_data(data, key = nil, iv = nil)
    @blocksize = 128 / 8
    @key = key.nil? ? (1..32).map{rand(255).chr}.join : key
    @iv  = iv.nil?  ? (1..16).map{rand(255).chr}.join : iv
    @mode = "AES-256-CBC"
    @data = Crypto.encrypt(data, @key, @iv, @mode)

    if(verbose)
      puts()
      puts("-" * 80)
      puts("Generated test data: #{data}")
      puts("-" * 80)
      puts("key: #{@key.unpack("H*")}")
      puts("iv:  #{@iv.unpack("H*")}")
      puts("enc: #{@data.unpack("H*")}")
      puts("-" * 80)
    end
  end

  def attempt_decrypt(iv, block)
      begin
        if(@delay > 0)
          sleep(@delay)
        end
        decrypted = Crypto.decrypt(block, @key, iv, @mode)
        return true
      rescue # TODO: Be more specific
        return false
      end
  end
end


require 'AES'

class TestModule
  attr_reader :iv, :blocksize, :data
  attr_accessor :verbose

  NAME = "TestModule(tm)"

  def initialize(verbose = false)
    @verbose = verbose
  end

  def aes_128_from_data(data, key = nil, iv = nil)
    @blocksize = AES::BLOCKSIZE
    @key = key.nil? ? (1..16).map{rand(255).chr}.join : key
    @iv  = iv.nil?  ? (1..16).map{rand(255).chr}.join : iv
    @data = AES.encrypt(data, @key, @iv, "AES-128-CBC")

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
    @blocksize = AES::BLOCKSIZE
    @key = key.nil? ? (1..16).map{rand(255).chr}.join : key
    @iv  = iv.nil?  ? (1..16).map{rand(255).chr}.join : iv
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

  def attempt_decrypt(iv, block)
      begin
        #sleep(0.0005)
        decrypted = AES.decrypt(block, @key, iv, "AES-128-CBC")
        return true
      rescue # TODO: Be more specific
        return false
      end
  end
end


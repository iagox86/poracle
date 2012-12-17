class Hex
  BYTE_NUMBER_LENGTH  = 8
  SPACES_BEFORE_HEX   = 2
  SPACES_BEFORE_ASCII = 2
  LINE_LENGTH         = 16

  attr_reader :pos
  attr_reader :old_pos

  def initialize(data, pos = 0)
    @data = data
    @pos = pos
    @old_pos = -1
  end
 
  def self.get_str(data)
    length = data.length
    out = ''
  
    0.upto(length - 1) do |i|
  
      if((i % LINE_LENGTH) == 0)
        if(i != 0)
          out = out + "\n"
        end
        out = out + ("%0#{BYTE_NUMBER_LENGTH}X" % i) + " " * SPACES_BEFORE_HEX
      end
  
      out = out + ("%02X " % data[i])
  
      if(((i + 1) % LINE_LENGTH) == 0)
        out = out + (" " * SPACES_BEFORE_ASCII)
        LINE_LENGTH.step(1, -1) do |j|
          out = out + ("%c" % ((data[i + 1 - j] > 0x20 && data[i + 1 - j] < 0x80) ? data[i + 1 - j] : ?.))
        end
      end
  
    end
  
    (length % LINE_LENGTH).upto(LINE_LENGTH - 1) do |i|
      out = out + ("   ") # The width of a hex character and a space
    end
    out = out + (' ' * SPACES_BEFORE_ASCII)
  
    (length - (length % LINE_LENGTH)).upto(length - 1) do |i|
      out = out + ("%c" % ((data[i] > 0x20 && data[i] < 0x80) ? data[i] : ?.)) # TODO: this won't work
    end
  
    out = out + ("\nLength: 0x%X (%d)\n" % [length, length])
  
    return out
  end

  def get_str()
    return Hex.get_str(@data)
  end
  
  def self.get_hex_coordinates(pos, offset = 0)
    pos = pos + offset
    x = BYTE_NUMBER_LENGTH + SPACES_BEFORE_HEX + ((pos % LINE_LENGTH) * 3)
    y = (pos / LINE_LENGTH)
  
    return [y, x]
  end

  def get_current_hex_coordinates(offset = 0)
    return Hex.get_hex_coordinates(@pos + offset)
  end
  
  def self.get_ascii_coordinates(pos, offset = 0)
    x = BYTE_NUMBER_LENGTH + SPACES_BEFORE_HEX + (LINE_LENGTH * 3) + SPACES_BEFORE_ASCII + (pos % LINE_LENGTH)
    y = (pos / LINE_LENGTH)
  
    return [y, x]
  end

  def get_ascii_coordinates(offset = 0)
    return Hex.get_ascii_coordinates(@pos + offset)
  end

  def columns
    return BYTE_NUMBER_LENGTH + SPACES_BEFORE_HEX + (3 * LINE_LENGTH) + SPACES_BEFORE_ASCII + LINE_LENGTH
  end

  def lines
    return (@data.size / 16) + 1
  end

  def set_pos_absolute(pos)
    # Remember the old position
    @old_pos = @pos

    # Make sure we haven't overflowed or underflowed
    pos = [0, pos].max
    pos = [@data.size - 1, pos].min

    # Set it 
    @pos = pos
  end
  private :set_pos_absolute

  def set_pos_relative(offset)
    set_pos_absolute(@pos + offset)
  end
  private :set_pos_relative

  def go_left
    set_pos_relative(-1)
  end

  def go_right
    set_pos_relative(+1)
  end

  def go_up
    set_pos_relative(-LINE_LENGTH)
  end

  def go_down
    set_pos_relative(+LINE_LENGTH)
  end
end
  


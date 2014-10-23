module CoRE
  module CoAP
    class Block
      VALID_SIZE = [16, 32, 64, 128, 256, 512, 1024].freeze
      MAX_NUM = (1048576 - 1).freeze

      attr_reader :num, :more, :size

      def initialize(*args)
        if args.size == 1
          @encoded = args.first.to_i
        else
          @decoded = []
          self.num, self.more, self.size = args
          @decoded = [self.num, self.more, self.size]
        end

        self
      end

      def chunk(data)
        data[@size * @num, @size]
      end

      def chunk_count(data)
        return 0 if data.nil? || data.empty?
        i = data.size % self.size == 0 ? 0 : 1
        data.size / self.size + i
      end

      def chunkify(data)
        Block.chunkify(data, self.size)
      end

      def decode
        if @encoded == 0
          @decoded = [0, false, 16]
        else
          @decoded = [@encoded >> 4, (@encoded & 8) == 8, 16 << (@encoded & 7)]
        end

        self.num, self.more, self.size = @decoded

        self
      end

      def encode
        @encoded = @num << 4 | (@more ? 1 : 0) << 3 | CoAP.number_of_bits_up_to(@size) - 4
      end

      def included_by?(body)
        return true if self.num == 0 && (body.nil? || body.empty?)
        self.num < chunk_count(body)
      end

      def last?(data)
        return true if data.nil? || data.empty?
        self.num == chunk_count(data) - 1
      end

      def more=(v)
        if @num > MAX_NUM
          raise ArgumentError, 'num MUST be < 1048576'
        end

        @more = !!v
        @decoded[1] = @more
      end

      def more?(data)
        return false if data.nil? || data.empty?
        data.bytesize > (self.num + 1) * self.size
      end

      def num=(v)
        @num = v.to_i
        @decoded[0] = @num
      end

      def size=(v)
        unless VALID_SIZE.include?(v.to_i)
          raise ArgumentError, 'size MUST be power of 2 between 16 and 1024.'
        end

        @size = v.to_i
        @decoded[2] = @size
      end

      def self.chunkify(data, size)
        data.bytes.each_slice(size).map { |c| c.pack('C*') }
      end
    end
  end
end

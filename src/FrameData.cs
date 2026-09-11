namespace V380Decoder.src
{
    public class FrameData
    {
        public byte RawType;   // fragment header type byte (0x00/0x01 H.264, 0x28/0x29 H.265, 0x1A audio PCMA, 0x18 audio AAC/ADTS)
        public uint FrameId;
        public ushort FrameType;
        public ushort FrameRate;
        public ulong Timestamp;
        public byte[] Payload;
        public bool IsKeyframe => RawType == 0x00 || RawType == 0x28;
        public bool IsH265 => RawType == 0x28 || RawType == 0x29;
        public bool IsAac => RawType == 0x18;
    }
}
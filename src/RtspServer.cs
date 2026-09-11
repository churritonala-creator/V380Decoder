using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace V380Decoder.src
{
    public class RtspServer
    {
        private readonly int port;
        private readonly bool secure;
        private readonly string username;
        private readonly string password;
        private TcpListener listener;
        private Thread acceptThread;
        private volatile bool running;

        // concurrent set of active sessions
        private readonly ConcurrentDictionary<int, RtspSession> sessions = new();
        private int nextId;

        // SPS/PPS from first keyframe – used for SDP fmtp line (H.264)
        private byte[] cachedSps, cachedPps;
        // VPS/SPS/PPS for H.265
        private byte[] cacheVps, cacheH265Sps, cacheH265Pps;
        // detected codec: false=H.264, true=H.265
        private bool isH265 = false;
        private readonly object sdpLock = new();

        // Frames since the last keyframe. Sent as a burst to new sessions so
        // they get a picture immediately instead of waiting for the next
        // keyframe (the camera GOP is ~80 frames / ~7 s).
        private readonly List<FrameData> gop = new();
        private const int GOP_MAX_FRAMES = 400;
        private readonly object gopLock = new();

        public RtspServer(int port, bool secure, string username, string password)
        {
            this.port = port;
            this.username = username;
            this.password = password;
            this.secure = secure;
        }

        public bool IsSecure => secure;
        public string Username => username;
        public string Password => password;

        public void Start()
        {
            string basicAuth = secure ? $"{username}:{password}@" : string.Empty;
            listener = new TcpListener(IPAddress.Any, port);
            listener.Start(10);
            running = true;
            acceptThread = new Thread(AcceptLoop) { IsBackground = true, Name = "rtsp-accept" };
            acceptThread.Start();
            Console.Error.WriteLine($"[RTSP] rtsp://{basicAuth}{NetworkHelper.GetLocalIPAddress()}:{port}/live");
        }

        void AcceptLoop()
        {
            while (running)
            {
                try
                {
                    var tcp = listener.AcceptTcpClient();
                    tcp.NoDelay = true;
                    int id = Interlocked.Increment(ref nextId);
                    var s = new RtspSession(id, tcp, this, secure);
                    sessions[id] = s;
                    s.Start();
                    s.OnClose += () => sessions.TryRemove(id, out _);
                }
                catch { }
            }
        }

        // Called from main receive loop for every complete video frame
        public void PushVideo(FrameData f)
        {
            if (f.RawType == 0x28 || f.RawType == 0x29)
            {
                // H.265 frames: cache VPS/SPS/PPS from first keyframe
                if (f.RawType == 0x28) CacheH265Params(f.Payload);
            }
            else
            {
                if (f.IsKeyframe) CacheSpsFromIdr(f.Payload);
            }

            lock (gopLock)
            {
                if (f.IsKeyframe) gop.Clear();
                if (f.IsKeyframe || gop.Count > 0)
                {
                    if (gop.Count < GOP_MAX_FRAMES) gop.Add(f);
                }
            }

            foreach (var s in sessions.Values) s.PushVideo(f);
        }

        // Copy of the current GOP (keyframe first), or empty if none yet
        public FrameData[] GetGop()
        {
            lock (gopLock) return gop.ToArray();
        }

        // Audio codec, learned from the first audio frame (PCMA vs AAC/ADTS).
        // For AAC the AudioSpecificConfig (SDP "config=") is derived from the ADTS header.
        private volatile bool audioKnown;
        private bool audioAac;
        private string aacConfigHex = "1588"; // AAC-LC 8 kHz mono (default for fw32)
        private int aacSampleRate = 8000, aacChannels = 1;
        public bool AudioKnown => audioKnown;

        // Called from main receive loop for every complete audio frame
        public void PushAudio(FrameData f)
        {
            if (!audioKnown)
            {
                lock (sdpLock)
                {
                    if (!audioKnown)
                    {
                        audioAac = f.IsAac;
                        if (f.IsAac && TryParseAdts(f.Payload, out int objType, out int sfIdx, out int ch))
                        {
                            int[] rates = { 96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350 };
                            aacSampleRate = sfIdx < rates.Length ? rates[sfIdx] : 8000;
                            aacChannels = ch == 0 ? 1 : ch;
                            // AudioSpecificConfig: objectType(5) sfIdx(4) channels(4) + 3 bits de relleno
                            int cfg = (objType << 11) | (sfIdx << 7) | (aacChannels << 3);
                            aacConfigHex = cfg.ToString("X4");
                        }
                        audioKnown = true;
                        Console.Error.WriteLine(audioAac
                            ? $"[RTSP] audio: AAC-LC {aacSampleRate} Hz ch={aacChannels} (config={aacConfigHex})"
                            : "[RTSP] audio: PCMA 8000 Hz");
                    }
                }
            }
            foreach (var s in sessions.Values) s.PushAudio(f);
        }

        // ADTS header: syncword(12) id(1) layer(2) protection_absent(1) profile(2) sfIdx(4) private(1) ch(3) ...
        internal static bool TryParseAdts(byte[] d, out int objType, out int sfIdx, out int ch)
        {
            objType = 2; sfIdx = 11; ch = 1;
            if (d == null || d.Length < 7 || d[0] != 0xFF || (d[1] & 0xF0) != 0xF0) return false;
            objType = (d[2] >> 6) + 1;
            sfIdx = (d[2] >> 2) & 0x0F;
            ch = ((d[2] & 1) << 2) | (d[3] >> 6);
            return true;
        }

        string AudioSdp()
        {
            if (audioAac)
                return
                    "m=audio 0 RTP/AVP 97\r\n" +
                    $"a=rtpmap:97 MPEG4-GENERIC/{aacSampleRate}/{aacChannels}\r\n" +
                    $"a=fmtp:97 streamtype=5;profile-level-id=1;mode=AAC-hbr;sizelength=13;indexlength=3;indexdeltalength=3;config={aacConfigHex}\r\n" +
                    "a=control:trackID=1\r\n";
            return
                "m=audio 0 RTP/AVP 8\r\n" +
                "a=rtpmap:8 PCMA/8000/1\r\n" +
                "a=control:trackID=1\r\n";
        }

        // ── H.264 SPS/PPS extraction ───────────────────────────────────
        void CacheSpsFromIdr(byte[] data)
        {
            lock (sdpLock)
            {
                if (cachedSps != null && cachedPps != null) return; // already cached
                ParseNals(data, (nalType, nal) =>
                {
                    if (nalType == 7 && cachedSps == null) cachedSps = nal;
                    if (nalType == 8 && cachedPps == null) cachedPps = nal;
                });
            }
        }

        // ── H.265 VPS/SPS/PPS extraction ────────────────────────────────
        void CacheH265Params(byte[] data)
        {
            lock (sdpLock)
            {
                if (cacheVps != null && cacheH265Sps != null && cacheH265Pps != null) return;
                isH265 = true;
                int i = 0, len = data.Length;
                while (i < len)
                {
                    int sc = FindStartCode(data, i);
                    if (sc < 0) break;
                    int scLen = (sc + 3 < len && data[sc + 2] == 1) ? 3 : 4;
                    int nalStart = sc + scLen;
                    if (nalStart >= len) break;
                    int next = FindStartCode(data, nalStart);
                    int nalEnd = next < 0 ? len : next;
                    if (nalStart + 1 >= nalEnd) { i = nalEnd; continue; }
                    int nalType = (data[nalStart] >> 1) & 0x3F; // H.265 NAL type
                    var nal = new byte[nalEnd - nalStart];
                    Array.Copy(data, nalStart, nal, 0, nal.Length);
                    if (nalType == 32 && cacheVps == null) cacheVps = nal;      // VPS
                    else if (nalType == 33 && cacheH265Sps == null) cacheH265Sps = nal; // SPS
                    else if (nalType == 34 && cacheH265Pps == null) cacheH265Pps = nal; // PPS
                    i = nalEnd;
                }
            }
        }

        public bool IsH265 => isH265;

        // Walk H.264 Annex-B start codes, call cb(nalType, nalBytes) for each NAL
        internal static void ParseNals(byte[] data, Action<int, byte[]> cb)
        {
            int i = 0, len = data.Length;
            while (i < len)
            {
                // find start code
                int sc = FindStartCode(data, i);
                if (sc < 0) break;
                int scLen = (sc + 3 < len && data[sc + 2] == 1) ? 3 : 4;
                int nalStart = sc + scLen;
                if (nalStart >= len) break;
                // find next start code
                int next = FindStartCode(data, nalStart);
                int nalEnd = next < 0 ? len : next;
                int nalType = data[nalStart] & 0x1F;
                var nal = new byte[nalEnd - nalStart];
                Array.Copy(data, nalStart, nal, 0, nal.Length);
                cb(nalType, nal);
                i = nalEnd;
            }
        }

        internal static void ParseNalsH265(byte[] data, Action<int, byte[]> cb)
        {
            int i = 0, len = data.Length;
            while (i < len)
            {
                int sc = FindStartCode(data, i);
                if (sc < 0) break;
                int scLen = (sc + 3 < len && data[sc + 2] == 1) ? 3 : 4;
                int nalStart = sc + scLen;
                if (nalStart >= len) break;
                int next = FindStartCode(data, nalStart);
                int nalEnd = next < 0 ? len : next;
                if (nalStart + 1 >= nalEnd) { i = nalEnd; continue; }
                int nalType = (data[nalStart] >> 1) & 0x3F; // H.265 NAL type
                var nal = new byte[nalEnd - nalStart];
                Array.Copy(data, nalStart, nal, 0, nal.Length);
                cb(nalType, nal);
                i = nalEnd;
            }
        }

        static int FindStartCode(byte[] d, int from)
        {
            for (int i = from; i + 3 < d.Length; i++)
            {
                if (d[i] == 0 && d[i + 1] == 0)
                {
                    if (d[i + 2] == 1) return i;
                    if (d[i + 2] == 0 && i + 3 < d.Length && d[i + 3] == 1) return i;
                }
            }
            return -1;
        }

        public string BuildSdp()
        {
            lock (sdpLock)
            {
                if (isH265 && cacheVps != null && cacheH265Sps != null && cacheH265Pps != null)
                {
                    string vpsB64 = Convert.ToBase64String(cacheVps);
                    string spsB64 = Convert.ToBase64String(cacheH265Sps);
                    string ppsB64 = Convert.ToBase64String(cacheH265Pps);
                    return
                        "v=0\r\n" +
                        "o=- 1 1 IN IP4 0.0.0.0\r\n" +
                        "s=V380 Live\r\n" +
                        "t=0 0\r\n" +
                        "a=recvonly\r\n" +
                        "m=video 0 RTP/AVP 96\r\n" +
                        "a=rtpmap:96 H265/90000\r\n" +
                        $"a=fmtp:96 packetization-mode=1;sprop-vps={vpsB64};sprop-sps={spsB64};sprop-pps={ppsB64}\r\n" +
                        "a=control:trackID=0\r\n" +
                        AudioSdp();
                }

                string fmtp = "";
                if (cachedSps != null && cachedPps != null)
                {
                    string spsB64 = Convert.ToBase64String(cachedSps);
                    string ppsB64 = Convert.ToBase64String(cachedPps);
                    // profile-level-id = first 3 bytes of SPS (after NAL header)
                    string pli = cachedSps.Length >= 3
                        ? $"{cachedSps[0]:X2}{cachedSps[1]:X2}{cachedSps[2]:X2}"
                        : "64001F";
                    fmtp = $"a=fmtp:96 packetization-mode=1;sprop-parameter-sets={spsB64},{ppsB64};profile-level-id={pli}\r\n";
                }
                return
                    "v=0\r\n" +
                    "o=- 1 1 IN IP4 0.0.0.0\r\n" +
                    "s=V380 Live\r\n" +
                    "t=0 0\r\n" +
                    "a=recvonly\r\n" +
                    "m=video 0 RTP/AVP 96\r\n" +
                    "a=rtpmap:96 H264/90000\r\n" +
                    fmtp +
                    "a=control:trackID=0\r\n" +
                    AudioSdp();
            }
        }

        public void Dispose()
        {
            running = false;
            try { listener?.Stop(); } catch { }
            foreach (var s in sessions.Values) s.Close();
        }
    }
}

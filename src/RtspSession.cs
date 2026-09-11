using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.Sockets;
using System.Text;

namespace V380Decoder.src
{
    public class RtspSession
    {
        private readonly int id;
        private readonly TcpClient tcp;
        private readonly NetworkStream ns;
        private readonly RtspServer server;
        private readonly bool secure;
        private bool authenticated;
        private Thread readThread;
        private volatile bool playing;
        private volatile bool alive = true;

        // interleaved channels negotiated in SETUP
        private byte videoCh = 0, audioCh = 2;

        // RTP state
        private ushort videoSeq, audioSeq;
        private uint videoSsrc = (uint)new Random().Next();
        private uint audioSsrc = (uint)new Random().Next();

        // RTP video timestamps come from a monotonic wall clock (90 kHz), so
        // playback speed follows the real (variable) camera frame rate.
        // Camera-provided timestamps are unreliable and cause DTS errors.
        private readonly Stopwatch _clock = Stopwatch.StartNew();
        private uint _audioRtsClock = 0;

        // Per-session send queue. The camera receive loop only enqueues;
        // a dedicated thread writes to the socket so a slow client never
        // stalls the camera stream or other sessions.
        private readonly BlockingCollection<(FrameData frame, bool audio, uint ts)> _queue = new();
        private Thread _sendThread;
        private const int MAX_QUEUE = 100;
        private bool _waitKeyframe;
        private readonly object _playLock = new();
        // Added to the wall clock so live frames always come after the burst
        private uint _tsOffset;

        public event Action OnClose;

        public RtspSession(int id, TcpClient tcp, RtspServer server, bool secure = false)
        {
            this.id = id; this.tcp = tcp; this.server = server;
            this.secure = secure;
            this.authenticated = !secure; // if not secure, auto-authenticate
            ns = tcp.GetStream();
        }

        public void Start()
        {
            readThread = new Thread(ReadLoop) { IsBackground = true, Name = $"rtsp-{id}" };
            readThread.Start();
            _sendThread = new Thread(SendLoop) { IsBackground = true, Name = $"rtsp-send-{id}" };
            _sendThread.Start();
        }

        public void Close()
        {
            alive = false;
            playing = false;
            try { _queue.CompleteAdding(); } catch { }
            try { tcp.Close(); } catch { }
            OnClose?.Invoke();
        }

        uint NowTs() => (uint)(_clock.ElapsedMilliseconds * 90) + _tsOffset;

        void SendLoop()
        {
            try
            {
                foreach (var (frame, audio, ts) in _queue.GetConsumingEnumerable())
                {
                    if (!alive) break;
                    if (audio) SendAudio(frame);
                    else SendVideo(frame, ts);
                }
            }
            catch { }
        }

        // ── RTSP request reader ──────────────────────────────────
        void ReadLoop()
        {
            var sb = new StringBuilder();
            var buf = new byte[4096];
            try
            {
                while (alive)
                {
                    int n = ns.Read(buf, 0, buf.Length);
                    if (n <= 0) break;
                    sb.Append(Encoding.ASCII.GetString(buf, 0, n));
                    string raw = sb.ToString();
                    int end;
                    while ((end = raw.IndexOf("\r\n\r\n", StringComparison.Ordinal)) >= 0)
                    {
                        string req = raw[..(end + 4)];
                        raw = raw[(end + 4)..];
                        HandleRequest(req);
                    }
                    sb.Clear(); sb.Append(raw);
                }
            }
            catch { }
            finally { Close(); }
        }

        // ── Authentication ──────────────────────────────────
        private bool CheckAuth(string authHeader)
        {
            if (string.IsNullOrEmpty(authHeader)) return false;

            var headerParts = authHeader.Split(':', 2);
            if (headerParts.Length != 2) return false;

            string authValue = headerParts[1].Trim();
            if (!authValue.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                return false;

            try
            {
                string encoded = authValue["Basic ".Length..].Trim();
                string credential = Encoding.ASCII.GetString(Convert.FromBase64String(encoded));
                var parts = credential.Split(':', 2);

                if (parts.Length == 2 &&
                    parts[0] == server.Username &&
                    parts[1] == server.Password)
                {
                    return true;
                }
            }
            catch { }

            return false;
        }

        void HandleRequest(string req)
        {
            string[] lines = req.Split("\r\n", StringSplitOptions.None);
            if (lines.Length == 0) return;

            string method = lines[0].Split(' ')[0];
            string url = lines[0].Split(' ').ElementAtOrDefault(1) ?? "";
            string cseq = lines.FirstOrDefault(l => l.StartsWith("CSeq:", StringComparison.OrdinalIgnoreCase))
                                  ?.Split(':', 2)[1].Trim() ?? "0";
            string transport = lines.FirstOrDefault(l => l.StartsWith("Transport:", StringComparison.OrdinalIgnoreCase)) ?? "";
            string authHeader = lines.FirstOrDefault(l => l.StartsWith("Authorization:", StringComparison.OrdinalIgnoreCase)) ?? "";

            // Check authentication for methods other than OPTIONS (if secure)
            if (secure && method != "OPTIONS" && !authenticated)
            {
                if (!CheckAuth(authHeader))
                {
                    Send($"RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\n" +
                         $"WWW-Authenticate: Basic realm=\"V380 Authentication\"\r\n\r\n");
                    return;
                }
                authenticated = true;
            }

            switch (method)
            {
                case "OPTIONS":
                    Reply(cseq, "Public: OPTIONS,DESCRIBE,SETUP,PLAY,TEARDOWN");
                    break;

                case "DESCRIBE":
                    {
                        string sdp = server.BuildSdp();
                        byte[] body = Encoding.ASCII.GetBytes(sdp);
                        Send($"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n" +
                             $"Content-Type: application/sdp\r\nContent-Length: {body.Length}\r\n\r\n{sdp}");
                        break;
                    }

                case "SETUP":
                    {
                        bool isAudio = url.Contains("trackID=1");
                        // Parse interleaved channels from client Transport header
                        // e.g. Transport: RTP/AVP/TCP;unicast;interleaved=0-1
                        byte ch = (byte)(isAudio ? 2 : 0);
                        var m = System.Text.RegularExpressions.Regex.Match(transport, @"interleaved=(\d+)-(\d+)");
                        if (m.Success) ch = byte.Parse(m.Groups[1].Value);

                        Reply(cseq,
                            $"Transport: RTP/AVP/TCP;unicast;interleaved={ch}-{ch + 1}",
                            "Session: 1");
                        break;
                    }

                case "PLAY":
                    Reply(cseq,
                        "Session: 1",
                        $"RTP-Info: url={url}/trackID=0;seq={videoSeq},url={url}/trackID=1;seq={audioSeq}");
                    lock (_playLock)
                    {
                        // Burst the buffered GOP (keyframe + deltas) with timestamps
                        // 1 ms apart so the client decodes it at once and shows a
                        // picture immediately. Live frames continue after it.
                        var gop = server.GetGop();
                        uint now = NowTs();
                        for (int i = 0; i < gop.Length; i++)
                            _queue.TryAdd((gop[i], false, now + (uint)(i * 90)));
                        _tsOffset += (uint)(gop.Length * 90);
                        _waitKeyframe = gop.Length == 0;
                        playing = true;
                        Console.Error.WriteLine($"[RTSP#{id}] playing (burst {gop.Length} frames)");
                    }
                    break;

                case "TEARDOWN":
                    Reply(cseq, "Session: 1");
                    Close();
                    break;

                default:
                    Send($"RTSP/1.0 501 Not Implemented\r\nCSeq: {cseq}\r\n\r\n");
                    break;
            }
        }

        void Reply(string cseq, params string[] headers)
        {
            var sb = new StringBuilder();
            sb.Append($"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\n");
            foreach (var h in headers) sb.Append(h + "\r\n");
            sb.Append("\r\n");
            Send(sb.ToString());
        }

        void Send(string s)
        {
            try
            {
                byte[] b = Encoding.ASCII.GetBytes(s);
                lock (ns) { ns.Write(b, 0, b.Length); ns.Flush(); }
            }
            catch { alive = false; }
        }

        // Called from the camera receive loop: enqueue only, never block
        public void PushVideo(FrameData f)
        {
            lock (_playLock)
            {
                if (!playing) return;

                // Client cannot keep up: drop until the next keyframe so the
                // decoder resyncs instead of accumulating latency.
                if (_queue.Count > MAX_QUEUE) _waitKeyframe = true;
                if (_waitKeyframe)
                {
                    if (!f.IsKeyframe) return;
                    _waitKeyframe = false;
                }
                _queue.TryAdd((f, false, NowTs()));
            }
        }

        public void PushAudio(FrameData f)
        {
            lock (_playLock)
            {
                if (!playing) return;
                if (_queue.Count > MAX_QUEUE) return;
                _queue.TryAdd((f, true, 0));
            }
        }

        // ── RTP video send  (H.264/H.265 Annex-B → RTP NAL/FU-A) ──────
        void SendVideo(FrameData f, uint rts)
        {
            if (f.IsH265)
            {
                PushVideoH265(f.Payload, rts);
                return;
            }

            RtspServer.ParseNals(f.Payload, (nalType, nal) =>
            {
                const int MTU = 1400;
                if (nal.Length <= MTU)
                {
                    // Single NAL unit packet
                    SendRtp(videoCh, 96, videoSeq++, rts, videoSsrc, nal, 0, nal.Length, marker: true);
                }
                else
                {
                    // FU-A fragmentation
                    byte nalHdr = nal[0];
                    byte fuInd = (byte)((nalHdr & 0xE0) | 28); // NRI from original, type=28
                    int offset = 1; // skip original NAL header
                    bool first = true;

                    while (offset < nal.Length)
                    {
                        int chunk = Math.Min(MTU - 2, nal.Length - offset);
                        bool last = offset + chunk >= nal.Length;

                        byte fuHdr = (byte)(nalHdr & 0x1F);              // NAL type
                        if (first) fuHdr |= 0x80;                        // S bit
                        if (last) fuHdr |= 0x40;                        // E bit

                        var frag = new byte[2 + chunk];
                        frag[0] = fuInd;
                        frag[1] = fuHdr;
                        Array.Copy(nal, offset, frag, 2, chunk);

                        SendRtp(videoCh, 96, videoSeq++, rts, videoSsrc,
                                frag, 0, frag.Length, marker: last);
                        offset += chunk;
                        first = false;
                    }
                }
            });
        }

        // ── H.265 RTP push ──────────────────────────────────────────────
        void PushVideoH265(byte[] data, uint rts)
        {
            RtspServer.ParseNalsH265(data, (nalType, nal) =>
            {
                const int MTU = 1400;
                // Non-VCL NAL types (32+): VPS, SPS, PPS, AUD, etc. — send as single units
                if (nalType >= 32)
                {
                    if (nal.Length <= MTU)
                    {
                        SendRtp(videoCh, 96, videoSeq++, rts, videoSsrc, nal, 0, nal.Length, marker: false);
                    }
                    return;
                }

                if (nal.Length <= MTU)
                {
                    // Single NAL unit packet
                    SendRtp(videoCh, 96, videoSeq++, rts, videoSsrc, nal, 0, nal.Length, marker: true);
                }
                else
                {
                    // H.265 FU (Fragmentation Unit) - type 49
                    byte nalHdr0 = nal[0];
                    byte nalHdr1 = nal.Length > 1 ? nal[1] : (byte)0;
                    byte fuIndicator = (byte)((nalHdr0 & 0x81) | (49 << 1)); // type=49 FU
                    int offset = 2; // 2-byte H.265 NAL header
                    bool first = true;

                    while (offset < nal.Length)
                    {
                        int chunk = Math.Min(MTU - 3, nal.Length - offset);
                        bool last = offset + chunk >= nal.Length;

                        // FU header byte
                        byte fuHdr = (byte)(nalType & 0x3F);
                        if (first) fuHdr |= 0x80; // S bit
                        if (last) fuHdr |= 0x40;  // E bit

                        var frag = new byte[3 + chunk];
                        frag[0] = fuIndicator;
                        frag[1] = nalHdr1; // keep second header byte
                        frag[2] = fuHdr;
                        Array.Copy(nal, offset, frag, 3, chunk);

                        SendRtp(videoCh, 96, videoSeq++, rts, videoSsrc,
                                frag, 0, frag.Length, marker: last);
                        offset += chunk;
                        first = false;
                    }
                }
            });
        }

        // ── RTP audio send  (PCMA raw samples) ──────────────────
        void SendAudio(FrameData f)
        {
            // Use synthetic RTP timestamps to prevent DTS discontinuities
            // 160 samples per chunk at 8 kHz = 20 ms of audio per RTP packet
            const int CHUNK = 160;
            for (int off = 0; off < f.Payload.Length; off += CHUNK)
            {
                int len = Math.Min(CHUNK, f.Payload.Length - off);
                SendRtp(audioCh, 8, audioSeq++, _audioRtsClock, audioSsrc,
                        f.Payload, off, len, marker: false);
                _audioRtsClock += (uint)CHUNK;
            }
        }

        // ── Low-level RTP sender with RTSP interleaved framing ───
        // RFC 2326 §10.12:  $ | channel (1B) | length (2B BE) | RTP packet
        void SendRtp(byte channel, byte pt, ushort seq, uint ts, uint ssrc,
                     byte[] payload, int offset, int length, bool marker)
        {
            var rtp = new byte[12 + length];
            rtp[0] = 0x80;
            rtp[1] = (byte)((marker ? 0x80 : 0) | (pt & 0x7F));
            rtp[2] = (byte)(seq >> 8);
            rtp[3] = (byte)seq;
            rtp[4] = (byte)(ts >> 24); rtp[5] = (byte)(ts >> 16);
            rtp[6] = (byte)(ts >> 8); rtp[7] = (byte)ts;
            rtp[8] = (byte)(ssrc >> 24); rtp[9] = (byte)(ssrc >> 16);
            rtp[10] = (byte)(ssrc >> 8); rtp[11] = (byte)ssrc;
            Array.Copy(payload, offset, rtp, 12, length);

            var frame = new byte[4 + rtp.Length];
            frame[0] = 0x24; // '$'
            frame[1] = channel;
            frame[2] = (byte)(rtp.Length >> 8);
            frame[3] = (byte)rtp.Length;
            Array.Copy(rtp, 0, frame, 4, rtp.Length);

            try { lock (ns) { ns.Write(frame, 0, frame.Length); ns.Flush(); } }
            catch { alive = false; }
        }
    }
}
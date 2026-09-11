using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace V380Decoder.src
{
    public class V380Client : IDisposable
    {
        public SnapshotManager snapshotManager { get; private set; }
        private TcpClient authClient, streamClient;
        private NetworkStream authStream, streamStream;
        private readonly string ip;
        private readonly int port;
        private readonly uint deviceId;
        private readonly string username, password;
        private readonly SourceStream source;
        private readonly OutputMode mode;
        private readonly bool enableMjpeg;
        private uint authTicket, sessionId;
        private ushort deviceVersion, communicationVersion;
        private int frameWidth = 1280;
        private int frameheight = 720;
        private byte[] aesKey = new byte[16];
        private bool needReconnect = false;
        private DeviceInfo deviceInfo;


        public V380Client(string ip, int port, uint deviceId, string username, string password, SourceStream source, OutputMode mode, bool enableMjpeg)
        {
            this.ip = ip;
            this.port = port;
            this.deviceId = deviceId;
            this.username = username;
            this.password = password;
            this.source = source;
            this.mode = mode;
            this.enableMjpeg = enableMjpeg;
            snapshotManager = new SnapshotManager();
            snapshotManager.SetMjpegActive(enableMjpeg);
        }

        public void Run(RtspServer rtsp, CancellationToken ct)
        {
            SetDeviceInfo();
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    int auth = GetAuthTicket();
                    if (auth == 0) continue;
                    if (auth == -1) break;

                    if (!StreamLogin())
                    {
                        Console.Error.WriteLine("[STREAM] Retrying...");
                        streamStream?.Close(); streamClient?.Close();
                        continue;
                    }

                    if (!StartStream())
                    {
                        Console.Error.WriteLine("[STREAM] Retrying...");
                        continue;
                    }

                    ReceiveFrames(mode, rtsp, ct);
                }
                catch (OperationCanceledException)
                {
                    Console.Error.WriteLine("[STREAM] Operation cancelled");
                    break;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine($"[ERROR] Fatal error: {ex.Message}");
                    Console.Error.WriteLine($"[ERROR] Stack trace: {ex.StackTrace}");
                    Thread.Sleep(3000);
                }
                finally
                {
                    Console.Error.WriteLine("[STREAM] Closing connection...");
                    streamStream?.Close(); streamClient?.Close();
                }
            }
        }

        public int GetAuthTicket()
        {
            try
            {
                authClient = new TcpClient();
                var r = authClient.BeginConnect(ip, port, null, null);
                if (!r.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5)))
                {
                    Console.Error.WriteLine("[AUTH] failed connecting to socket. retrying...");
                    return 0;
                }
                authClient.EndConnect(r);
                authStream = authClient.GetStream();

                var encryptedPassword = GeneratePassword(password);
                var userBytes = Encoding.ASCII.GetBytes(username);
                var cmd1167 = new byte[520];
                WriteUInt32LE(cmd1167, 0, 1167); // command
                if (source == SourceStream.Lan)
                {
                    WriteUInt32LE(cmd1167, 4, 120); // unknown1
                    cmd1167[8] = 31; // unknown2 (version?)
                    WriteUInt32LE(cmd1167, 9, 1); // unknown3            
                    WriteUInt32LE(cmd1167, 13, deviceId); // deviceId
                    Array.Copy(userBytes, 0, cmd1167, 49, Math.Min(userBytes.Length, 32)); //username
                    Array.Copy(encryptedPassword, 0, cmd1167, 81, Math.Min(encryptedPassword.Length, 64)); //password
                }
                else
                {
                    WriteUInt32LE(cmd1167, 4, 1022); // unknown1
                    cmd1167[8] = 31; // unknown2 (version?)
                    WriteUInt32LE(cmd1167, 9, 1); // unknown3 
                    WriteUInt32LE(cmd1167, 13, deviceId); // deviceId
                    var hostnameBytes = Encoding.ASCII.GetBytes($"{deviceId}.nvdvr.net");
                    Array.Copy(hostnameBytes, 0, cmd1167, 17, Math.Min(hostnameBytes.Length, 50)); //hostname
                    WriteUInt32LE(cmd1167, 67, (uint)port); //port
                    Array.Copy(userBytes, 0, cmd1167, 71, Math.Min(userBytes.Length, 32)); //username
                    Array.Copy(encryptedPassword, 0, cmd1167, 103, Math.Min(encryptedPassword.Length, 64)); //password
                }
                if (!SendData(authStream, cmd1167))
                {
                    Console.Error.WriteLine("[AUTH] failed send request. retrying...");
                    return 0;
                }

                var resp = ReceiveData(authStream, 256);
                if (resp == null || resp.Length < 256)
                {
                    Console.Error.WriteLine("[AUTH] failed receive response. retrying...");
                    return 0;
                }

                uint respCmd = ReadUInt32LE(resp, 0);
                if (respCmd != 1168)
                {
                    Console.Error.WriteLine($"[AUTH] invalid response cmd: {respCmd} (expected 1168). retrying...");
                    return 0;
                }
                uint loginResult = ReadUInt32LE(resp, 4);
                if (loginResult != 1001)
                {
                    if (loginResult == 1011)
                        Console.Error.WriteLine($"[AUTH] invalid username. exiting...");
                    else if (loginResult == 1012)
                        Console.Error.WriteLine($"[AUTH] invalid password. exiting...");
                    else if (loginResult == 1018)
                        Console.Error.WriteLine($"[AUTH] invalid device id. exiting...");
                    else
                        Console.Error.WriteLine($"[AUTH] login failed result: {loginResult} (expected 1001). exiting...");

                    return -1;
                }

                uint resultValue = ReadUInt32LE(resp, 8);
                byte version = resp[12];
                uint ticket = ReadUInt32LE(resp, 13);
                uint session = ReadUInt32LE(resp, 17);
                byte deviceType = resp[21];
                byte camType = resp[22];
                uint vendorId = ReadUInt16LE(resp, 23);
                uint isDomainExists = resp[25];
                byte[] domainBytes = new byte[32];
                Array.Copy(resp, 26, domainBytes, 0, 32);
                string domain = Encoding.ASCII.GetString(domainBytes).TrimEnd('\0');

                LogUtils.debug($"[AUTH] response success");
                LogUtils.debug($"[AUTH] cmd: {respCmd}");
                LogUtils.debug($"[AUTH] result: {loginResult}");
                LogUtils.debug($"[AUTH] authTicket: {ticket} (0x{ticket:X})");
                LogUtils.debug($"[AUTH] resultValue: {resultValue}");
                LogUtils.debug($"[AUTH] version: {version}");
                LogUtils.debug($"[AUTH] session: {session}");
                LogUtils.debug($"[AUTH] deviceType: {deviceType}");
                LogUtils.debug($"[AUTH] camType: {camType}");
                LogUtils.debug($"[AUTH] vendorId: {vendorId}");
                LogUtils.debug($"[AUTH] isDomainExists: {isDomainExists}");
                LogUtils.debug($"[AUTH] domain: {domain}");

                deviceVersion = version;
                sessionId = session;
                authTicket = ticket;

                Console.Error.WriteLine($"[AUTH] success ticket={authTicket} deviceVersion={deviceVersion}");
                authStream.Close(); authClient.Close();
                return 1;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[AUTH] Error: {ex.Message}");
                return 0;
            }
            finally
            {
                authStream?.Close(); authClient?.Close();
            }
        }


        public bool StreamLogin()
        {
            streamClient = new TcpClient
            {
                NoDelay = true,
                ReceiveBufferSize = 0x20000,
                SendBufferSize = 0x10000
            };
            var r = streamClient.BeginConnect(ip, port, null, null);
            if (!r.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5)))
            {
                Console.Error.WriteLine("[STREAM] failed connecting to socket. retrying...");
                return false;
            }
            ;
            streamClient.EndConnect(r);
            streamStream = streamClient.GetStream();

            var cmd301 = new byte[256];
            WriteUInt32LE(cmd301, 0, 301);
            if (source == SourceStream.Lan)
            {
                WriteUInt32LE(cmd301, 4, deviceId); //device id
                WriteUInt32LE(cmd301, 8, 0); //unknown1 
                WriteUInt16LE(cmd301, 12, 20); //unknown2 
                WriteUInt32LE(cmd301, 14, authTicket); //auth ticket
                WriteUInt32LE(cmd301, 22, 4097); //audio 4096=off, 4097=on
                WriteUInt32LE(cmd301, 26, 1);    //quality  0=SD, 1=HD
            }
            else
            {
                WriteUInt32LE(cmd301, 4, 1022); //unknown1 
                var hostnameBytes = Encoding.ASCII.GetBytes($"{deviceId}.nvdvr.net");
                Array.Copy(hostnameBytes, 0, cmd301, 8, Math.Min(hostnameBytes.Length, 50)); //hostname
                WriteUInt32LE(cmd301, 58, (uint)port); //port
                WriteUInt32LE(cmd301, 62, deviceId); //device id
                WriteUInt32LE(cmd301, 66, authTicket); // auth ticket
                WriteUInt32LE(cmd301, 70, sessionId); // session id
                WriteUInt32LE(cmd301, 74, 1); //quality 0=SD, 1=HD
                cmd301[78] = 20; //unknown2 
                WriteUInt32LE(cmd301, 79, 1); //unknown23
            }

            if (!SendData(streamStream, cmd301))
            {
                Console.Error.WriteLine("[STREAM] login failed send request");
                return false;
            }

            var resp401 = ReceiveData(streamStream, 412);

            if (resp401 == null || resp401.Length < 8)
            {
                Console.Error.WriteLine("[STREAM] login failed receive response");
                return false;
            }
            var respCmd = ReadUInt32LE(resp401, 0);
            if (respCmd != 401)
            {
                Console.Error.WriteLine($"[STREAM] login invalid response cmd: {respCmd} (expected 401)");
                return false;
            }

            int result = (int)ReadUInt32LE(resp401, 4);
            if (result == -11 || result == -12)
            {
                Console.Error.WriteLine($"[STREAM] login failed result={result}");
                return false;
            }

            LogUtils.debug($"[STREAM] login response success");
            LogUtils.debug($"[STREAM] login cmd: {respCmd}");
            if (source == SourceStream.Lan)
            {
                ushort version = ReadUInt16LE(resp401, 8);
                uint width = ReadUInt32LE(resp401, 10);
                uint height = ReadUInt32LE(resp401, 14);
                uint maxPackSize = ReadUInt32LE(resp401, 18);
                byte audioFreq = resp401[22];
                byte audioBits = resp401[23];
                byte audioChannels = resp401[24];
                communicationVersion = version;
                frameWidth = (int)width;
                frameheight = (int)height;
                LogUtils.debug($"[STREAM] login result: {result}");
                LogUtils.debug($"[STREAM] login version: {version}");
                LogUtils.debug($"[STREAM] login width: {width}");
                LogUtils.debug($"[STREAM] login height: {height}");
                LogUtils.debug($"[STREAM] login maxPackSize: {maxPackSize}");
                LogUtils.debug($"[STREAM] login audioFreq: {audioFreq}");
                LogUtils.debug($"[STREAM] login audioBits: {audioBits}");
                LogUtils.debug($"[STREAM] login audioChannels: {audioChannels}");
            }

            if (deviceVersion > 30) GenerateMediaKey(authTicket);
            Console.Error.WriteLine($"[STREAM] login OK");
            return true;
        }

        public bool StartStream()
        {
            Console.Error.WriteLine($"[STREAM] starting stream...");
            var cmd303 = new byte[256];
            WriteUInt32LE(cmd303, 0, 303);
            WriteUInt16LE(cmd303, 4, 0x3001);
            return SendData(streamStream, cmd303);
        }

        public void ReceiveFrames(OutputMode mode, RtspServer rtsp, CancellationToken ct)
        {
            bool needDecrypt = deviceVersion > 30;

            var videoFrags = new List<byte>();
            var audioFrags = new List<byte>();
            ushort videoTotal = 0, audioTotal = 0;

            var header12 = new byte[12];
            var payloadBuf = new byte[65536];

            // stdout is used only for Video or Audio output modes
            Stream stdout = (mode == OutputMode.Video || mode == OutputMode.Audio)
                ? Console.OpenStandardOutput()
                : null;

            Console.Error.WriteLine($"[RECV] mode={mode} decrypt={needDecrypt} communicationVersion={communicationVersion}");

            try
            {
                while (!ct.IsCancellationRequested)
                {
                    if (needReconnect)
                    {
                        Console.Error.WriteLine($"[STREAM] lost, reconnecting... ");
                        try { streamStream?.Close(); streamClient?.Close(); } catch { }
                        if (!StreamLogin()) break;
                        if (!StartStream()) break;
                        needReconnect = false;
                    }

                    // 12-byte fragment header
                    if (ReadExact(streamStream, header12, 0, 12) < 12) continue;

                    if (header12[0] != 0x7F)
                    {
                        continue;
                    }

                    byte type = header12[1];
                    ushort totalFrame = ReadUInt16LE(header12, 3);
                    ushort curFrame = ReadUInt16LE(header12, 5);
                    ushort payLen = ReadUInt16LE(header12, 7);

                    if (payLen == 0 || payLen > 20000 || totalFrame == 0 || curFrame >= totalFrame)
                    {
                        Console.Error.WriteLine($"[SKIP] invalid header type=0x{type:X2} total={totalFrame} cur={curFrame} len={payLen}");
                        continue;
                    }

                    if (payloadBuf.Length < payLen) payloadBuf = new byte[payLen];
                    if (ReadExact(streamStream, payloadBuf, 0, payLen) < payLen) continue;

                    // VIDEO  0x00=I-frame  0x01=P-frame  0x28/0x29=alt-video (fw v32+)
                    if (type == 0x00 || type == 0x01 || type == 0x28 || type == 0x29)
                    {
                        if (curFrame == 0) { videoFrags.Clear(); videoTotal = totalFrame; }
                        if (totalFrame != videoTotal) { videoFrags.Clear(); videoTotal = totalFrame; }

                        for (int i = 0; i < payLen; i++) videoFrags.Add(payloadBuf[i]);

                        if (curFrame != totalFrame - 1) continue;
                        if (videoFrags.Count < 16) { videoFrags.Clear(); continue; }

                        byte[] full = videoFrags.ToArray();
                        videoFrags.Clear();

                        byte[] payload;
                        bool isIFrame;

                        //parse inner 16-byte frame header
                        uint frameId = ReadUInt32LE(full, 0);
                        ushort frameType = ReadUInt16LE(full, 4);
                        ushort frameRate = ReadUInt16LE(full, 6);
                        ulong timestamp = ReadUInt64LE(full, 8);

                        payload = new byte[full.Length - 16];
                        Array.Copy(full, 16, payload, 0, payload.Length);
                        isIFrame = type == 0x00 || type == 0x28;

                        if (needDecrypt)
                        {
                            if (communicationVersion == 21)
                                DecryptMediaPre2k(payload, payload.Length, 1);
                            else
                                DecryptVideoFrame(payload, payload.Length);
                        }

                        // Search for H.264/H.265 Annex-B start code within first 16 bytes
                        int scPos = -1;
                        int searchEnd = Math.Min(16, payload.Length - 3);
                        for (int i = 0; i < searchEnd; i++)
                        {
                            if (payload[i] == 0 && payload[i + 1] == 0 && payload[i + 2] == 1)
                            {
                                scPos = i;
                                if (i > 0 && payload[i - 1] == 0)
                                    scPos = i - 1;
                                break;
                            }
                        }

                        if (scPos < 0)
                        {
                            Console.Error.WriteLine($"[VIDEO] bad start code, len={payload.Length}");
                            continue;
                        }

                        if (scPos > 0)
                        {
                            byte[] trimmed = new byte[payload.Length - scPos];
                            Array.Copy(payload, scPos, trimmed, 0, trimmed.Length);
                            payload = trimmed;
                        }

                        snapshotManager.UpdateFrame(payload, frameWidth, frameheight, isIFrame, isH265: type == 0x28 || type == 0x29);

                        var fd = new FrameData
                        {
                            RawType = type,
                            FrameId = frameId,
                            FrameType = frameType,
                            FrameRate = frameRate,
                            Timestamp = timestamp,
                            Payload = payload
                        };

                        if (isIFrame && LogUtils.enableDebug)
                        {
                            // El timestamp de la cámara es hora local en ms (epoch + offset TZ)
                            long nowLocal = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + (long)TimeZoneInfo.Local.GetUtcOffset(DateTime.UtcNow).TotalMilliseconds;
                            LogUtils.debug($"[LAT] keyframe cam->decoder {nowLocal - (long)timestamp} ms (frameId={frameId})");
                        }
                        if (mode == OutputMode.Video)
                        {
                            stdout.Write(payload, 0, payload.Length);
                            stdout.Flush();
                        }
                        else if (mode == OutputMode.Rtsp)
                        {
                            rtsp?.PushVideo(fd);
                        }
                    }

                    // AUDIO  0x1A = PCM a-law 8 kHz (fw <=31)
                    //        0x18 = AAC-LC en ADTS (fw 32; 8 kHz mono, 1024 muestras/frame)
                    // Ambos van cifrados con AES-ECB (media key) sobre la parte alineada a 16 bytes.
                    else if (type == 0x1A || type == 0x18)
                    {
                        if (curFrame == 0) { audioFrags.Clear(); audioTotal = totalFrame; }
                        if (totalFrame != audioTotal) { audioFrags.Clear(); audioTotal = totalFrame; }

                        for (int i = 0; i < payLen; i++) audioFrags.Add(payloadBuf[i]);

                        if (curFrame != totalFrame - 1) continue;
                        if (audioFrags.Count < 16) { audioFrags.Clear(); continue; }

                        byte[] full = audioFrags.ToArray();
                        audioFrags.Clear();

                        //parse inner 16-byte frame header
                        uint frameId = ReadUInt32LE(full, 0);
                        ushort frameType = ReadUInt16LE(full, 4);
                        ushort frameRate = ReadUInt16LE(full, 6);
                        ulong timestamp = ReadUInt64LE(full, 8);

                        byte[] payload = new byte[full.Length - 16];
                        Array.Copy(full, 16, payload, 0, payload.Length);

                        if (needDecrypt)
                        {
                            if (communicationVersion == 21)
                                DecryptMediaPre2k(payload, payload.Length, 1);
                            else
                                DecryptAudioFrame(payload, payload.Length);
                        }

                        var fd = new FrameData
                        {
                            RawType = type,
                            FrameId = frameId,
                            FrameType = frameType,
                            FrameRate = frameRate,
                            Timestamp = timestamp,
                            Payload = payload
                        };

                        if (mode == OutputMode.Audio)
                        {
                            stdout.Write(payload, 0, payload.Length);
                            stdout.Flush();
                        }
                        else if (mode == OutputMode.Rtsp)
                        {
                            rtsp?.PushAudio(fd);
                        }
                    }
                    else if (type == 0x5B)
                    {
                        continue;
                    }
                    else
                    {
                        LogUtils.debug($"[FRAME] unknown type=0x{type:X2} len={payLen}");
                    }
                }
            }
            catch (OperationCanceledException)
            {
                Console.Error.WriteLine("[RECV] Operation cancelled");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RECV] {ex.Message}");
            }
        }

        private void DecryptVideoFrame(byte[] data, int length)
        {
            using var aes = Aes.Create();
            aes.Key = aesKey; aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None;
            using var dec = aes.CreateDecryptor();
            for (int offset = 0; offset + 64 <= length; offset += 80)
                for (int i = 0; i < 4; i++)
                    dec.TransformBlock(data, offset + i * 16, 16, data, offset + i * 16);
        }

        private void DecryptAudioFrame(byte[] data, int length)
        {
            int alignedSize = (length / 16) * 16;
            if (alignedSize == 0) return;

            using var aes = Aes.Create();
            aes.Key = aesKey;
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;
            using var dec = aes.CreateDecryptor();
            for (int i = 0; i < alignedSize; i += 16)
                dec.TransformBlock(data, i, 16, data, i);
        }

        // Not tested
        private void DecryptMediaPre2k(byte[] data, int length, int mode)
        {
            int decryptLength;
            if (mode == 0 && length > 2048)
            {
                decryptLength = 2048;
            }
            else
            {
                decryptLength = (length / 16) * 16;
            }
            if (decryptLength > 0)
            {
                using var aes = Aes.Create();
                aes.Key = aesKey;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                using var decryptor = aes.CreateDecryptor();
                decryptor.TransformBlock(data, 0, decryptLength, data, 0);
            }
        }

        void GenerateMediaKey(uint ticket)
        {
            WriteUInt32LE(aesKey, 0, ticket);
            WriteUInt64LE(aesKey, 4, 0x618123462c14795c);
            WriteUInt32LE(aesKey, 12, 0x82800df0);
            LogUtils.debug($"[KEY] {BitConverter.ToString(aesKey).Replace("-", "")}");
        }

        byte[] GeneratePassword(string pw)
        {
            byte[] sk = Encoding.ASCII.GetBytes("macrovideo+*#!^@");
            var rng = new Random();
            byte[] rk = new byte[16];
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            for (int i = 0; i < 16; i++) rk[i] = (byte)chars[rng.Next(chars.Length)];

            var pb = Encoding.ASCII.GetBytes(pw);
            var pad = new byte[48];
            Array.Copy(pb, pad, Math.Min(pb.Length, 48));

            void Enc(byte[] key)
            {
                using var a = Aes.Create();
                a.Key = key; a.Mode = CipherMode.ECB; a.Padding = PaddingMode.None;
                using var e = a.CreateEncryptor();
                for (int i = 0; i < 48; i += 16) e.TransformBlock(pad, i, 16, pad, i);
            }
            Enc(sk); Enc(rk);

            var out_ = new byte[64];
            Array.Copy(rk, 0, out_, 0, 16);
            Array.Copy(pad, 0, out_, 16, 48);
            return out_;
        }

        private readonly object _sendLock = new();
        bool SendData(NetworkStream s, byte[] d)
        {
            try { lock (_sendLock) { s.Write(d, 0, d.Length); s.Flush(); } return true; }
            catch (Exception ex) { Console.Error.WriteLine($"[SEND] {ex.Message}"); return false; }
        }

        byte[] ReceiveData(NetworkStream s, int max)
        {
            var buf = new byte[max]; int tot = 0;
            var deadline = DateTime.Now.AddSeconds(5);
            while (DateTime.Now < deadline)
            {
                if (s.DataAvailable || tot > 0)
                {
                    int n = s.Read(buf, tot, max - tot);
                    if (n <= 0) break;
                    tot += n;
                    if (tot >= 16) break;
                }
                else Thread.Sleep(10);
            }
            if (tot == 0) return null;
            var r = new byte[tot]; Array.Copy(buf, r, tot); return r;
        }

        int ReadExact(NetworkStream s, byte[] buf, int off, int cnt)
        {
            int tot = 0;
            var deadline = DateTime.Now.AddSeconds(6);
            while (tot < cnt)
            {
                if (DateTime.Now > deadline)
                {
                    needReconnect = true;
                    return tot;
                }
                if (!s.DataAvailable)
                {
                    Thread.Sleep(10);
                    continue;
                }
                int n = s.Read(buf, off + tot, cnt - tot);
                if (n <= 0) break;
                tot += n;
            }
            return tot;
        }

        void WriteUInt32LE(byte[] b, int o, uint v) { b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24); }
        void WriteUInt16LE(byte[] b, int o, ushort v) { b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); }
        void WriteUInt64LE(byte[] b, int o, ulong v) { for (int i = 0; i < 8; i++) b[o + i] = (byte)(v >> (i * 8)); }
        uint ReadUInt32LE(byte[] b, int o) => (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24));
        ushort ReadUInt16LE(byte[] b, int o) => (ushort)(b[o] | (b[o + 1] << 8));
        ulong ReadUInt64LE(byte[] b, int o) { ulong v = 0; for (int i = 0; i < 8; i++) v |= ((ulong)b[o + i]) << (i * 8); return v; }

        public bool PtzRight() => SendControl(V380Commands.PTZ_RIGHT);
        public bool PtzLeft() => SendControl(V380Commands.PTZ_LEFT);
        public bool PtzUp() => SendControl(V380Commands.PTZ_UP);
        public bool PtzDown() => SendControl(V380Commands.PTZ_DOWN);
        public bool PtzStop() => SendControl(V380Commands.PTZ_STOP);
        public bool LightOn() => SendControl(V380Commands.LIGHT_ON);
        public bool LightOff() => SendControl(V380Commands.LIGHT_OFF);
        public bool LightAuto() => SendControl(V380Commands.LIGHT_AUTO);
        public bool ImageColor() => SendControl(V380Commands.IMAGE_COLOR);
        public bool ImageBW() => SendControl(V380Commands.IMAGE_BW);
        public bool ImageAuto() => SendControl(V380Commands.IMAGE_AUTO);
        public bool ImageFlip() => SendControl(V380Commands.IMAGE_FLIP);
        // PTZ avanzado (opcode 0xc7): auto-seguimiento y presets/posiciones.
        // Estructura capturada de la app: c7 00 00 00 <sub u16 LE> 00 00 <param u16 LE> + ceros.
        public bool PtzAdvanced(ushort sub, ushort param)
        {
            var cmd = new byte[16];
            cmd[0] = 0xc7;
            cmd[4] = (byte)sub; cmd[5] = (byte)(sub >> 8);
            cmd[8] = (byte)param; cmd[9] = (byte)(param >> 8);
            return SendControl(cmd);
        }
        public bool TrackOn() => PtzAdvanced(1001, 0);      // c7 e903 p0  (auto-seguimiento ON)
        public bool GotoPreset(ushort id) => PtzAdvanced(1002, id); // c7 ea03 p<id> (posición A=1100, B=1101)
        public bool AlarmOn() => SendControl(V380Commands.ALARM_ON);
        public bool AlarmOff() => SendControl(V380Commands.ALARM_OFF);

        // ── Two-way audio (hablar) ──────────────────────────────────────
        // Recibe PCM16 mono 8kHz, lo encodea IMA ADPCM 4-bit, lo cifra con la
        // media key (AES-128-ECB) y lo manda con el header 0xb4 + seq incremental.
        // Formato obtenido capturando el intercom real de la app V380 (fw32).
        static readonly int[] ADPCM_STEP = {
            7,8,9,10,11,12,13,14,16,17,19,21,23,25,28,31,34,37,41,45,50,55,60,66,73,80,88,97,107,118,
            130,143,157,173,190,209,230,253,279,307,337,371,408,449,494,544,598,658,724,796,876,963,
            1060,1166,1282,1411,1552,1707,1878,2066,2272,2499,2749,3024,3327,3660,4026,4428,4871,5358,
            5894,6484,7132,7845,8630,9493,10442,11487,12635,13899,15289,16818,18500,20350,22385,24623,
            27086,29794,32767 };
        static readonly int[] ADPCM_IDX = { -1,-1,-1,-1,2,4,6,8,-1,-1,-1,-1,2,4,6,8 };
        int _encPred = 0, _encIndex = 0, _talkSeq = 0;
        readonly List<byte> _talkBuf = new();
        readonly object _talkLock = new();

        System.Threading.CancellationTokenSource _talkCts;
        TcpClient _talkClient;
        NetworkStream _talkStream;
        public void BeginTalk()
        {
            EndTalk();
            lock (_talkLock) { _encPred = 0; _encIndex = 0; _talkSeq = 0; _talkBuf.Clear(); }
            // Conexión DEDICADA para el talk (la app usa una conexión aparte del video).
            try
            {
                _talkClient = new TcpClient { NoDelay = true };
                var ar = _talkClient.BeginConnect(ip, port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(4))) { EndTalk(); return; }
                _talkClient.EndConnect(ar);
                _talkStream = _talkClient.GetStream();
                // cmd 377 -> habilita el canal de audio de subida; respuesta cmd 477 (16B).
                var cmd377 = new byte[256];
                WriteUInt32LE(cmd377, 0, 377);
                WriteUInt32LE(cmd377, 4, deviceId);
                WriteUInt32LE(cmd377, 8, authTicket);
                _talkStream.Write(cmd377, 0, 256); _talkStream.Flush();
                var r = new byte[16]; int tot = 0;
                var dl = DateTime.Now.AddSeconds(3);
                while (tot < 16 && DateTime.Now < dl) { if (!_talkStream.DataAvailable) { Thread.Sleep(5); continue; } int n = _talkStream.Read(r, tot, 16 - tot); if (n <= 0) break; tot += n; }
                LogUtils.debug($"[TALK] 377 resp={BitConverter.ToString(r, 0, tot)}");
            }
            catch (Exception e) { Console.Error.WriteLine($"[TALK] connect fail: {e.Message}"); EndTalk(); return; }
            _talkCts = new System.Threading.CancellationTokenSource();
            var ct = _talkCts.Token;
            Task.Run(async () => { await TalkSender(ct); });
        }
        public void EndTalk()
        {
            try { _talkCts?.Cancel(); } catch { }
            lock (_talkLock) { _talkBuf.Clear(); }
            try { _talkStream?.Close(); } catch { }
            try { _talkClient?.Close(); } catch { }
            _talkStream = null; _talkClient = null;
        }

        // Envía un frame cada ~64ms (ritmo real de 512 muestras @ 8kHz) para no
        // inundar la cámara. El buffer actúa de cola; PushTalkPcm solo lo llena.
        async Task TalkSender(System.Threading.CancellationToken ct)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            long next = 0;
            while (!ct.IsCancellationRequested)
            {
                byte[] frame = null;
                lock (_talkLock)
                {
                    // Bloque IMA ADPCM WAV estándar: 505 muestras -> 256 bytes
                    // (header 4B: predictor int16 LE + step index + reservado) + 252B datos.
                    if (_talkBuf.Count >= 1010)
                    {
                        var sm = new short[505];
                        for (int k = 0; k < 505; k++) sm[k] = (short)(_talkBuf[k * 2] | (_talkBuf[k * 2 + 1] << 8));
                        _talkBuf.RemoveRange(0, 1010);
                        var block = new byte[256];
                        _encPred = sm[0];
                        block[0] = (byte)(sm[0] & 0xff); block[1] = (byte)((sm[0] >> 8) & 0xff);
                        block[2] = (byte)_encIndex; block[3] = 0;
                        for (int i = 0; i < 252; i++)
                        {
                            byte lo = EncodeAdpcm(sm[1 + i * 2]);
                            byte hi = EncodeAdpcm(sm[2 + i * 2]);
                            block[4 + i] = (byte)(lo | (hi << 4));
                        }
                        EncryptAudioFrame(block, 256);
                        _talkSeq = (_talkSeq % 255) + 1;
                        frame = new byte[16 + 256];
                        frame[0] = 0xb4; frame[4] = 0x01; frame[6] = 0x16; frame[14] = 0x01; frame[15] = (byte)_talkSeq;
                        Array.Copy(block, 0, frame, 16, 256);
                    }
                }
                if (frame != null && _talkStream != null)
                    try { _talkStream.Write(frame, 0, frame.Length); _talkStream.Flush(); } catch { break; }
                next += 63;
                long wait = next - sw.ElapsedMilliseconds;
                if (wait < 1) wait = 1; if (wait > 100) { wait = 63; next = sw.ElapsedMilliseconds + 63; }
                try { await Task.Delay((int)wait, ct); } catch { break; }
            }
        }

        byte EncodeAdpcm(short sample)
        {
            int step = ADPCM_STEP[_encIndex];
            int diff = sample - _encPred;
            int sign = 0; if (diff < 0) { sign = 8; diff = -diff; }
            int delta = 0, vpdiff = step >> 3;
            if (diff >= step) { delta |= 4; diff -= step; vpdiff += step; }
            step >>= 1; if (diff >= step) { delta |= 2; diff -= step; vpdiff += step; }
            step >>= 1; if (diff >= step) { delta |= 1; vpdiff += step; }
            _encPred += (sign != 0) ? -vpdiff : vpdiff;
            if (_encPred > 32767) _encPred = 32767; else if (_encPred < -32768) _encPred = -32768;
            delta |= sign;
            _encIndex += ADPCM_IDX[delta];
            if (_encIndex < 0) _encIndex = 0; else if (_encIndex > 88) _encIndex = 88;
            return (byte)delta;
        }

        void EncryptAudioFrame(byte[] data, int length)
        {
            int aligned = (length / 16) * 16; if (aligned == 0) return;
            using var aes = System.Security.Cryptography.Aes.Create();
            aes.Key = aesKey; aes.Mode = System.Security.Cryptography.CipherMode.ECB;
            aes.Padding = System.Security.Cryptography.PaddingMode.None;
            using var enc = aes.CreateEncryptor();
            for (int i = 0; i < aligned; i += 16) enc.TransformBlock(data, i, 16, data, i);
        }

        // Empuja PCM16LE mono 8kHz al buffer; el pacer (TalkSender) manda a ritmo real.
        public void PushTalkPcm(byte[] data, int len)
        {
            if (_talkStream == null) return;
            lock (_talkLock)
            {
                for (int i = 0; i < len; i++) _talkBuf.Add(data[i]);
                // Cap anti-flood: nunca más de ~0.5s en cola.
                if (_talkBuf.Count > 8192) _talkBuf.RemoveRange(0, _talkBuf.Count - 8192);
            }
        }

        private bool SendControl(byte[] payload)
        {
            if (streamStream == null) return false;
            return SendData(streamStream, payload);
        }

        public string GetDeviceId()
        {
            return deviceId.ToString();
        }

        public string GetDeviceVersion()
        {
            return deviceVersion.ToString();
        }

        public DeviceInfo GetDeviceInfo()
        {
            return deviceInfo;
        }

        public void SetDeviceInfo()
        {
            var discovery = new DeviceDiscovery();
            var devices = discovery.Discover();
            foreach (var dev in devices)
            {
                if (dev.DevId == deviceId.ToString())
                {
                    deviceInfo = dev;
                    break;
                }
            }
        }

        public void Dispose()
        {
            authStream?.Close(); authClient?.Close();
            streamStream?.Close(); streamClient?.Close();
            snapshotManager?.Dispose();
        }
    }
}
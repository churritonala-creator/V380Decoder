using System.Diagnostics;
using H264Sharp;
using SixLabors.ImageSharp;
using SixLabors.ImageSharp.Formats.Jpeg;
using SixLabors.ImageSharp.PixelFormats;

namespace V380Decoder.src
{
    public class SnapshotManager : IDisposable
    {
        // ── shared state ──────────────────────────────────────────
        private readonly object _lock = new();
        private byte[] _cachedJpeg = null;
        private int _width, _height;

        // ── mjpeg subscribers ─────────────────────────────────────
        private readonly List<Action<byte[]>> _subscribers = new();
        private readonly object _subLock = new();
        private readonly object _ffmpegLock = new();

        // ── decode pipeline ───────────────────────────────────────
        private readonly bool _useFFmpeg;
        private readonly CancellationTokenSource _cts = new();

        // H264Sharp path
        private H264Decoder _decoder;
        private bool _decoderReady = false;

        // FFmpeg path
        private Process _ffmpegProc;
        private Stream _ffmpegStdin;

        // Frame queue 
        private readonly System.Threading.Channels.Channel<(byte[] data, bool isIFrame)> _queue =
        System.Threading.Channels.Channel.CreateBounded<(byte[], bool)>(
        new System.Threading.Channels.BoundedChannelOptions(30)
        {
            FullMode = System.Threading.Channels.BoundedChannelFullMode.DropOldest,
            SingleReader = true
        });

        // SPS/PPS for prepend to I-frame (H264Sharp path)
        private byte[] _sps, _pps;

        private bool _mjpegActive = false;
        private byte[] _lastIFrame = null;
        // H.265 keyframes carry VPS/SPS/PPS inline, so no SPS/PPS prepend is needed
        private bool _isH265 = false;
        private readonly SemaphoreSlim _snapshotSem = new(1, 1);

        public SnapshotManager()
        {
            _useFFmpeg = IsFFmpegAvailable();
            LogUtils.debug($"[SNAP] decoder={(_useFFmpeg ? "FFmpeg" : "H264Sharp")}");

            if (_useFFmpeg)
                StartFFmpegPipe();
            else
                _decoder = new H264Decoder();

            Task.Run(() => DecodeLoop(_cts.Token));
        }

        // ── public API ────────────────────────────────────────────

        public void SetMjpegActive(bool active)
        {
            _mjpegActive = active;
            LogUtils.debug($"[SNAP] MJPEG {(active ? "enable" : "disabled")}");
        }

        public void UpdateFrame(byte[] h264Frame, int width, int height, bool isIFrame, bool isH265 = false)
        {
            lock (_lock)
            {
                _width = width;
                _height = height;
                _isH265 = isH265;
            }

            if (isIFrame)
            {
                if (!isH265) ExtractSpsAndPps(h264Frame);
                lock (_lock) { _lastIFrame = (byte[])h264Frame.Clone(); }
            }

            if (!_mjpegActive) return;

            if (_useFFmpeg)
            {
                try
                {
                    // Write asynchronously so we never block the camera receive loop
                    Task.Run(() =>
                    {
                        lock (_ffmpegLock)
                        {
                            _ffmpegStdin?.Write(h264Frame, 0, h264Frame.Length);
                            _ffmpegStdin?.Flush();
                        }
                    });
                }
                catch (Exception ex) { LogUtils.debug($"[SNAP] FFmpeg write error: {ex.Message}"); }
            }
            else
            {
                _queue.Writer.TryWrite(((byte[])h264Frame.Clone(), isIFrame));
            }
        }

        public byte[] GetSnapshot()
        {
            lock (_lock) { return _cachedJpeg; }
        }

        public async Task<byte[]> GetSnapshotAsync(int timeoutMs = 5000)
        {
            if (_mjpegActive)
            {
                lock (_lock) { return _cachedJpeg; }
            }

            if (!await _snapshotSem.WaitAsync(timeoutMs))
            {
                lock (_lock) { return _cachedJpeg; }
            }

            try
            {
                byte[] iFrame;
                int w, h;
                bool h265;
                lock (_lock) { iFrame = _lastIFrame; w = _width; h = _height; h265 = _isH265; }

                if (iFrame == null || (!h265 && (_sps == null || _pps == null)))
                {
                    lock (_lock) { return _cachedJpeg; }
                }

                if (h265 && !_useFFmpeg)
                {
                    // H264Sharp cannot decode HEVC
                    lock (_lock) { return _cachedJpeg; }
                }

                byte[] input = h265 ? iFrame : PrependSpsAndPps(iFrame);

                byte[] jpeg = _useFFmpeg
                    ? await DecodeOneFrameFFmpeg(input, h265)
                    : DecodeH264Sharp(input, isIFrame: true);

                if (jpeg != null)
                    lock (_lock) { _cachedJpeg = jpeg; }

                lock (_lock) { return _cachedJpeg; }
            }
            finally
            {
                _snapshotSem.Release();
            }
        }

        public IDisposable Subscribe(Action<byte[]> callback)
        {
            lock (_subLock) _subscribers.Add(callback);
            return new Subscription(() => { lock (_subLock) _subscribers.Remove(callback); });
        }

        // ── decode loop ───────────────────────────────────────────

        private async Task DecodeLoop(CancellationToken ct)
        {
            if (_useFFmpeg)
                return;

            await foreach (var (data, isIFrame) in _queue.Reader.ReadAllAsync(ct))
            {
                try
                {
                    var jpeg = DecodeH264Sharp(data, isIFrame);
                    if (jpeg != null)
                    {
                        lock (_lock) { _cachedJpeg = jpeg; }
                        Notify(jpeg);
                    }
                }
                catch (Exception ex)
                {
                    LogUtils.debug($"[SNAP] DecodeLoop error: {ex.Message}");
                }
            }
        }

        // ── H264Sharp ─────────────────────────────────────────────

        private byte[] DecodeH264Sharp(byte[] h264Data, bool isIFrame)
        {
            if (!_decoderReady)
            {
                _decoder.Initialize();
                _decoderReady = true;
            }

            int w, h;
            lock (_lock) { w = _width; h = _height; }

            byte[] input = (isIFrame && _sps != null && _pps != null)
                ? PrependSpsAndPps(h264Data)
                : h264Data;

            var rgb = new RgbImage(ImageFormat.Bgr, w, h);
            bool ok = _decoder.Decode(input, 0, input.Length, false, out DecodingState state, ref rgb);

            bool hasOutput = ok && (
                state == DecodingState.dsErrorFree ||
                state == DecodingState.dsDataErrorConcealed
            );

            if (!hasOutput)
            {
                LogUtils.debug($"[SNAP] H264Sharp skip: {state}");
                return null;
            }

            return ToJpeg(rgb.GetBytes(), w, h);
        }

        // ── FFmpeg persistent pipe ────────────────────────────────

        private void StartFFmpegPipe()
        {
            var psi = new ProcessStartInfo
            {
                FileName = "ffmpeg",
                Arguments = "-hide_banner -loglevel error " +
                            "-i pipe:0 " +
                            "-q:v 4 -f image2pipe -vcodec mjpeg pipe:1",
                UseShellExecute = false,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };

            _ffmpegProc = Process.Start(psi)!;
            _ffmpegStdin = _ffmpegProc.StandardInput.BaseStream;

            Task.Run(() => ReadFFmpegOutput(_ffmpegProc.StandardOutput.BaseStream, _cts.Token));
            LogUtils.debug("[SNAP] FFmpeg pipe started");
        }

        private async Task<byte[]> DecodeOneFrameFFmpeg(byte[] h264Data, bool h265 = false)
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "ffmpeg",
                    Arguments = "-hide_banner -loglevel error " +
                                (h265 ? "-f hevc " : "-f h264 ") +
                                "-i pipe:0 " +
                                "-frames:v 1 -q:v 2 -f image2 pipe:1",
                    UseShellExecute = false,
                    RedirectStandardInput = true,
                    RedirectStandardOutput = true,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi)!;
                await proc.StandardInput.BaseStream.WriteAsync(h264Data);
                proc.StandardInput.Close();

                using var ms = new MemoryStream();
                await proc.StandardOutput.BaseStream.CopyToAsync(ms);
                await proc.WaitForExitAsync();

                return ms.Length > 0 ? ms.ToArray() : null;
            }
            catch (Exception ex)
            {
                LogUtils.debug($"[SNAP] Snapshot FFmpeg error: {ex.Message}");
                return null;
            }
        }

        private void ReadFFmpegOutput(Stream stdout, CancellationToken ct)
        {
            var buf = new List<byte>(256_000);
            var tmp = new byte[8192];

            try
            {
                while (!ct.IsCancellationRequested)
                {
                    int n = stdout.Read(tmp, 0, tmp.Length);
                    if (n == 0) break;

                    buf.AddRange(new ArraySegment<byte>(tmp, 0, n));

                    int start = FindBytes(buf, 0xFF, 0xD8);
                    if (start < 0) continue;

                    int end = FindBytes(buf, 0xFF, 0xD9, start + 2);
                    if (end < 0) continue;

                    int jpegLen = end + 2 - start;
                    var jpeg = buf.GetRange(start, jpegLen).ToArray();
                    buf.RemoveRange(0, end + 2);

                    if (jpeg.Length > 1000)
                    {
                        lock (_lock) { _cachedJpeg = jpeg; }
                        Notify(jpeg);
                    }
                }
            }
            catch (Exception ex)
            {
                LogUtils.debug($"[SNAP] FFmpeg output error: {ex.Message}");
            }
        }

        private static int FindBytes(List<byte> buf, byte b0, byte b1, int from = 0)
        {
            for (int i = from; i < buf.Count - 1; i++)
                if (buf[i] == b0 && buf[i + 1] == b1) return i;
            return -1;
        }

        // ── helpers ───────────────────────────────────────────────

        private void ExtractSpsAndPps(byte[] h264Data)
        {
            var nals = FindNalUnits(h264Data);
            foreach (var nal in nals)
            {
                if (nal.Length == 0) continue;
                int t = nal[0] & 0x1F;
                if (t == 7) { _sps = (byte[])nal.Clone(); LogUtils.debug($"[SNAP] SPS {_sps.Length}b"); }
                if (t == 8) { _pps = (byte[])nal.Clone(); LogUtils.debug($"[SNAP] PPS {_pps.Length}b"); }
            }
        }

        private static List<byte[]> FindNalUnits(byte[] data)
        {
            var result = new List<byte[]>();
            int i = 0;
            while (i < data.Length - 4)
            {
                if (data[i] == 0 && data[i + 1] == 0 && data[i + 2] == 0 && data[i + 3] == 1)
                {
                    int start = i + 4, end = start;
                    while (end < data.Length - 4)
                    {
                        if (data[end] == 0 && data[end + 1] == 0 && data[end + 2] == 0 && data[end + 3] == 1) break;
                        end++;
                    }
                    if (end >= data.Length - 4) end = data.Length;
                    var nal = new byte[end - start];
                    Array.Copy(data, start, nal, 0, nal.Length);
                    result.Add(nal);
                    i = end;
                }
                else i++;
            }
            return result;
        }

        private byte[] PrependSpsAndPps(byte[] idrFrame)
        {
            byte[] sc = { 0x00, 0x00, 0x00, 0x01 };
            using var ms = new MemoryStream();
            ms.Write(sc); ms.Write(_sps);
            ms.Write(sc); ms.Write(_pps);
            ms.Write(idrFrame);
            return ms.ToArray();
        }

        private static byte[] ToJpeg(byte[] bgr, int w, int h)
        {
            using var img = Image.LoadPixelData<Rgb24>(bgr, w, h);
            using var ms = new MemoryStream();
            img.Save(ms, new JpegEncoder { Quality = 80 });
            return ms.ToArray();
        }

        private void Notify(byte[] jpeg)
        {
            List<Action<byte[]>> subs;
            lock (_subLock) subs = new(_subscribers);
            foreach (var s in subs) try { s(jpeg); } catch { }
        }

        private bool IsFFmpegAvailable()
        {
            try
            {
                var process = new Process
                {
                    StartInfo = new ProcessStartInfo
                    {
                        FileName = "ffmpeg",
                        Arguments = "-version",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    }
                };

                process.Start();
                bool exited = process.WaitForExit(2000);
                return exited && process.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        // ── dispose ───────────────────────────────────────────────

        public void Dispose()
        {
            _cts.Cancel();
            _queue.Writer.Complete();

            try { _ffmpegStdin?.Close(); } catch { }
            try { _ffmpegProc?.WaitForExit(2000); } catch { }
            try { _ffmpegProc?.Kill(); } catch { }
            _ffmpegProc?.Dispose();

            _decoder?.Dispose();
        }

        private class Subscription(Action onDispose) : IDisposable
        {
            public void Dispose() => onDispose();
        }
    }
}
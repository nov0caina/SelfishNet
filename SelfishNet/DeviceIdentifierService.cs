using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using SharpPcap;
using SharpPcap.LibPcap;

namespace SelfishNet
{
    public sealed class DeviceIdentifierService : IDeviceIdentifierService
    {
        private readonly ConcurrentDictionary<string, string> _hostnameCache = new();
        private readonly PcList _pcList;
        private readonly LibPcapLiveDevice _nic;
        private LibPcapLiveDevice _mdnsDevice;
        private Thread _mdnsThread;
        private volatile bool _isMdnsListening;

        private const int DnsTimeoutMs = 800;
        private const int NetBiosTimeoutMs = 1500;
        private const int SsdpTimeoutMs = 2000;

        public DeviceIdentifierService(LibPcapLiveDevice nic, PcList pcList)
        {
            _nic = nic ?? throw new ArgumentNullException(nameof(nic));
            _pcList = pcList ?? throw new ArgumentNullException(nameof(pcList));
        }

        // ──────────────────────────────────────────────
        //  Main identification pipeline
        // ──────────────────────────────────────────────

        public async Task IdentifyDeviceAsync(PC device, CancellationToken ct = default)
        {
            if (device == null) return;

            // Layer 1: OUI lookup (instant, < 0.1ms)
            byte[] macBytes = device.Mac?.GetAddressBytes();
            if (macBytes != null)
            {
                string vendor = OuiDatabase.Lookup(macBytes);
                if (vendor != null)
                {
                    device.Vendor = vendor;
                }
                else if (OuiDatabase.IsRandomizedMac(macBytes))
                {
                    device.Vendor = "Randomized MAC";
                }
            }

            // Layer 2: Reverse DNS (async, up to 800ms)
            if (device.Ip != null)
            {
                string hostname = await ResolveHostnameAsync(device.Ip, ct).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(hostname))
                {
                    device.Hostname = hostname;
                }
            }

            // Layer 3: NetBIOS name query (async, up to 1500ms)
            // Only try if DNS didn't resolve a useful hostname
            if (string.IsNullOrEmpty(device.Hostname) && device.Ip != null)
            {
                string netbiosName = await ResolveNetBiosNameAsync(device.Ip, ct).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(netbiosName))
                {
                    device.Hostname = netbiosName;
                    Console.WriteLine($"[NetBIOS] {device.Ip}: {netbiosName}");
                }
            }

            // Layer 4: SSDP probe (async, up to 2000ms)
            // Only try if still no hostname
            if (string.IsNullOrEmpty(device.Hostname) && device.Ip != null)
            {
                string ssdpName = await ProbeSsdpAsync(device.Ip, ct).ConfigureAwait(false);
                if (!string.IsNullOrEmpty(ssdpName))
                {
                    device.Hostname = ssdpName;
                    Console.WriteLine($"[SSDP] {device.Ip}: {ssdpName}");
                }
            }

            // Layer 5: Device type heuristic
            device.DeviceCategory = InferDeviceType(device);
        }

        // ──────────────────────────────────────────────
        //  Layer 2: Reverse DNS with strict timeout
        // ──────────────────────────────────────────────

        private async Task<string> ResolveHostnameAsync(IPAddress ip, CancellationToken ct)
        {
            string ipStr = ip.ToString();

            // Check cache first (O(1))
            if (_hostnameCache.TryGetValue(ipStr, out string cached))
            {
                return cached;
            }

            try
            {
                var dnsTask = Dns.GetHostEntryAsync(ipStr);
                var completed = await Task.WhenAny(dnsTask, Task.Delay(DnsTimeoutMs, ct)).ConfigureAwait(false);

                if (completed != dnsTask)
                {
                    // Timeout — cache empty to avoid retrying
                    _hostnameCache.TryAdd(ipStr, string.Empty);
                    return null;
                }

                var entry = await dnsTask.ConfigureAwait(false);

                string hostname = entry.HostName;

                // Don't cache if hostname is just the IP address repeated
                if (hostname != null && hostname != ipStr)
                {
                    _hostnameCache.TryAdd(ipStr, hostname);
                    return hostname;
                }
            }
            catch (OperationCanceledException)
            {
                // Timeout — cache empty to avoid retrying
            }
            catch (SocketException)
            {
                // No PTR record — expected for many devices
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DNS] Resolve failed for {ipStr}: {ex.Message}");
            }

            _hostnameCache.TryAdd(ipStr, string.Empty);
            return null;
        }

        // ──────────────────────────────────────────────
        //  Layer 3: NetBIOS Name Query (UDP port 137)
        // ──────────────────────────────────────────────

        /// <summary>
        /// Sends a NetBIOS Name Service status query to the target IP.
        /// Windows, many Android devices, and some IoT devices respond
        /// with their configured hostname. Single UDP packet, ~150 bytes.
        /// </summary>
        private async Task<string> ResolveNetBiosNameAsync(IPAddress ip, CancellationToken ct)
        {
            string cacheKey = $"nb_{ip}";
            if (_hostnameCache.TryGetValue(cacheKey, out string cached))
            {
                return cached;
            }

            try
            {
                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = NetBiosTimeoutMs;

                // NetBIOS Node Status Request (RFC 1002)
                // Transaction ID: 0x0001, Flags: 0x0000, Questions: 1
                // NBSTAT query for wildcard name "*" (encoded as CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)
                byte[] query = new byte[]
                {
                    0x00, 0x01, // Transaction ID
                    0x00, 0x00, // Flags: query
                    0x00, 0x01, // Questions: 1
                    0x00, 0x00, // Answer RRs: 0
                    0x00, 0x00, // Authority RRs: 0
                    0x00, 0x00, // Additional RRs: 0
                    // Name: * (wildcard) encoded as NBNS
                    0x20, // Name length (32)
                    0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                    0x00, // Name terminator
                    0x00, 0x21, // Type: NBSTAT (0x0021)
                    0x00, 0x01, // Class: IN
                };

                var endpoint = new IPEndPoint(ip, 137);
                await udp.SendAsync(query, query.Length, endpoint).ConfigureAwait(false);

                // Wait for response with timeout
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(NetBiosTimeoutMs);

                var receiveTask = udp.ReceiveAsync();
                var timeoutTask = Task.Delay(NetBiosTimeoutMs, cts.Token);
                var completed = await Task.WhenAny(receiveTask, timeoutTask).ConfigureAwait(false);

                if (completed != receiveTask)
                {
                    _hostnameCache.TryAdd(cacheKey, string.Empty);
                    return null;
                }

                var result = await receiveTask.ConfigureAwait(false);
                string name = ParseNetBiosResponse(result.Buffer);

                _hostnameCache.TryAdd(cacheKey, name ?? string.Empty);
                return name;
            }
            catch (OperationCanceledException) { }
            catch (SocketException) { }
            catch (ObjectDisposedException) { }
            catch (Exception ex)
            {
                Console.WriteLine($"[NetBIOS] Probe failed for {ip}: {ex.Message}");
            }

            _hostnameCache.TryAdd(cacheKey, string.Empty);
            return null;
        }

        /// <summary>
        /// Parses a NetBIOS Node Status Response to extract the first hostname.
        /// The name table starts at byte offset 57 (after header + resource record).
        /// Each entry is 18 bytes: 15 bytes name + 1 byte suffix + 2 bytes flags.
        /// </summary>
        private static string ParseNetBiosResponse(byte[] data)
        {
            // Minimum: header(12) + name(34) + type(2) + class(2) + ttl(4) + rdlength(2) + numNames(1) + 1 entry(18)
            if (data == null || data.Length < 75) return null;

            try
            {
                // Skip to answer section
                // After the query echo, the answer resource record starts
                // Name pointer or repeated name, then type(2), class(2), ttl(4), rdlength(2)
                int pos = 12; // Skip header

                // Skip the name field (may be a pointer 0xC0 0x0C or full name)
                if (pos < data.Length && (data[pos] & 0xC0) == 0xC0)
                {
                    pos += 2; // Compressed name pointer
                }
                else
                {
                    // Skip full name
                    while (pos < data.Length && data[pos] != 0) pos++;
                    pos++; // Skip null terminator
                }

                // Skip Type(2) + Class(2) + TTL(4) + RDLength(2) = 10 bytes
                pos += 10;

                if (pos >= data.Length) return null;

                // Number of name entries
                int numNames = data[pos];
                pos++;

                // Read first non-group name entry
                for (int i = 0; i < numNames && pos + 18 <= data.Length; i++)
                {
                    // 15-byte name + 1 byte suffix type + 2 byte flags
                    string name = Encoding.ASCII.GetString(data, pos, 15).TrimEnd();
                    byte suffixType = data[pos + 15];
                    ushort flags = (ushort)((data[pos + 16] << 8) | data[pos + 17]);
                    bool isGroup = (flags & 0x8000) != 0;

                    pos += 18;

                    // Skip group names and special names — we want the workstation name (suffix 0x00)
                    if (!isGroup && suffixType == 0x00 && !string.IsNullOrWhiteSpace(name))
                    {
                        return name;
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[NetBIOS] Parse error: {ex.Message}");
            }

            return null;
        }

        // ──────────────────────────────────────────────
        //  Layer 4: SSDP Discovery (UDP port 1900)
        // ──────────────────────────────────────────────

        /// <summary>
        /// Sends a unicast SSDP M-SEARCH to the target device.
        /// Smart TVs, game consoles, media players, and many IoT devices respond
        /// with their friendly name and device type in the response headers.
        /// </summary>
        private async Task<string> ProbeSsdpAsync(IPAddress ip, CancellationToken ct)
        {
            string cacheKey = $"ssdp_{ip}";
            if (_hostnameCache.TryGetValue(cacheKey, out string cached))
            {
                return cached;
            }

            try
            {
                using var udp = new UdpClient();
                udp.Client.ReceiveTimeout = SsdpTimeoutMs;

                // Unicast M-SEARCH directly to the device
                string msearch =
                    "M-SEARCH * HTTP/1.1\r\n" +
                    $"HOST: {ip}:1900\r\n" +
                    "MAN: \"ssdp:discover\"\r\n" +
                    "MX: 1\r\n" +
                    "ST: ssdp:all\r\n" +
                    "\r\n";

                byte[] data = Encoding.UTF8.GetBytes(msearch);
                var endpoint = new IPEndPoint(ip, 1900);
                await udp.SendAsync(data, data.Length, endpoint).ConfigureAwait(false);

                // Try to receive a response
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(SsdpTimeoutMs);

                var receiveTask = udp.ReceiveAsync();
                var timeoutTask = Task.Delay(SsdpTimeoutMs, cts.Token);
                var completed = await Task.WhenAny(receiveTask, timeoutTask).ConfigureAwait(false);

                if (completed != receiveTask)
                {
                    _hostnameCache.TryAdd(cacheKey, string.Empty);
                    return null;
                }

                var result = await receiveTask.ConfigureAwait(false);
                string response = Encoding.UTF8.GetString(result.Buffer);
                string name = ParseSsdpFriendlyName(response);

                _hostnameCache.TryAdd(cacheKey, name ?? string.Empty);
                return name;
            }
            catch (OperationCanceledException) { }
            catch (SocketException) { }
            catch (ObjectDisposedException) { }
            catch (Exception ex)
            {
                Console.WriteLine($"[SSDP] Probe failed for {ip}: {ex.Message}");
            }

            _hostnameCache.TryAdd(cacheKey, string.Empty);
            return null;
        }

        /// <summary>
        /// Extracts a friendly device name from an SSDP response.
        /// Looks for SERVER header which often contains device model/brand.
        /// </summary>
        private static string ParseSsdpFriendlyName(string response)
        {
            if (string.IsNullOrEmpty(response)) return null;

            // Try to extract SERVER header (e.g., "SERVER: Roku/12.0 UPnP/1.0")
            string[] lines = response.Split('\n');
            foreach (string line in lines)
            {
                string trimmed = line.Trim();

                if (trimmed.StartsWith("SERVER:", StringComparison.OrdinalIgnoreCase))
                {
                    string server = trimmed.Substring(7).Trim();
                    // Clean up common noise
                    // "Linux/3.14 UPnP/1.0 IpBridge/1.28.0" → "IpBridge"
                    // "Roku/12.0 UPnP/1.0" → "Roku"
                    string[] parts = server.Split(' ');
                    foreach (string part in parts)
                    {
                        string p = part.Trim();
                        // Skip generic OS/protocol identifiers
                        if (p.StartsWith("UPnP", StringComparison.OrdinalIgnoreCase)) continue;
                        if (p.StartsWith("Linux", StringComparison.OrdinalIgnoreCase)) continue;
                        if (p.StartsWith("Windows", StringComparison.OrdinalIgnoreCase)) continue;
                        if (p.StartsWith("DLNADOC", StringComparison.OrdinalIgnoreCase)) continue;
                        if (p.StartsWith("HTTP", StringComparison.OrdinalIgnoreCase)) continue;
                        if (string.IsNullOrWhiteSpace(p)) continue;

                        // Take the first meaningful token, strip version
                        int slashIdx = p.IndexOf('/');
                        return slashIdx > 0 ? p.Substring(0, slashIdx) : p;
                    }
                }
            }

            return null;
        }

        // ──────────────────────────────────────────────
        //  Passive mDNS listener (port 5353)
        // ──────────────────────────────────────────────

        public void StartMdnsListener()
        {
            if (_isMdnsListening) return;

            try
            {
                // Open a separate handle to avoid filter conflicts with ARP listener
                _mdnsDevice = new LibPcapLiveDevice(_nic.Interface);
                _mdnsDevice.Open(DeviceModes.Promiscuous, 500);
                _mdnsDevice.Filter = "udp port 5353";

                _isMdnsListening = true;
                _mdnsThread = new Thread(MdnsListenerLoop) { IsBackground = true };
                _mdnsThread.Start();
                Console.WriteLine("[INFO] mDNS passive listener started.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[mDNS] Failed to start listener: {ex.Message}");
                _isMdnsListening = false;
            }
        }

        public void StopMdnsListener()
        {
            if (!_isMdnsListening) return;
            _isMdnsListening = false;
            _mdnsThread?.Join(TimeSpan.FromSeconds(3));
            _mdnsThread = null;

            try { _mdnsDevice?.Close(); } catch { }
            _mdnsDevice = null;
            Console.WriteLine("[INFO] mDNS listener stopped.");
        }

        private void MdnsListenerLoop()
        {
            while (_isMdnsListening)
            {
                try
                {
                    var status = _mdnsDevice.GetNextPacket(out PacketCapture capture);
                    if (status != GetPacketStatus.PacketRead) continue;

                    var raw = capture.GetPacket().Data;
                    // Minimum: 14 (eth) + 20 (ip) + 8 (udp) + 12 (dns header) = 54
                    if (raw.Length < 54) continue;

                    // Extract source IP from IP header (offset 26)
                    byte[] srcIp = new byte[4];
                    Array.Copy(raw, 26, srcIp, 0, 4);

                    // Parse mDNS response for hostnames
                    // DNS payload starts at offset 42 (14 eth + 20 ip + 8 udp)
                    string name = TryParseMdnsName(raw, 42);
                    if (string.IsNullOrEmpty(name)) continue;

                    // Find matching device and update hostname
                    PC device = _pcList.GetDeviceByIp(srcIp);
                    if (device != null && string.IsNullOrEmpty(device.Hostname))
                    {
                        device.Hostname = name;
                        // Re-infer device type with new hostname
                        device.DeviceCategory = InferDeviceType(device);
                        Console.WriteLine($"[mDNS] {device.Ip}: {name}");
                    }
                }
                catch (Exception ex)
                {
                    if (_isMdnsListening)
                        Console.WriteLine($"[mDNS ERROR] {ex.Message}");
                }
            }
        }

        /// <summary>
        /// Extracts the first query/answer name from an mDNS packet.
        /// Parses DNS name labels (length-prefixed) from raw bytes.
        /// </summary>
        private static string TryParseMdnsName(byte[] raw, int dnsOffset)
        {
            if (raw.Length <= dnsOffset + 12) return null;

            // Skip DNS header (12 bytes) to reach first question/answer
            int pos = dnsOffset + 12;
            if (pos >= raw.Length) return null;

            // Read DNS name labels
            var nameBuilder = new StringBuilder(64);
            int safety = 0;

            while (pos < raw.Length && safety++ < 20)
            {
                byte labelLen = raw[pos];
                if (labelLen == 0) break;

                // Pointer (compression) — skip
                if ((labelLen & 0xC0) == 0xC0) break;

                if (pos + 1 + labelLen > raw.Length) break;

                if (nameBuilder.Length > 0) nameBuilder.Append('.');

                for (int i = 0; i < labelLen; i++)
                {
                    char c = (char)raw[pos + 1 + i];
                    nameBuilder.Append(c);
                }
                pos += 1 + labelLen;
            }

            string fullName = nameBuilder.ToString();
            if (string.IsNullOrEmpty(fullName)) return null;

            // Extract friendly name: "iPhone-de-Carlos._companion-link._tcp.local" → "iPhone-de-Carlos"
            // Remove service type suffixes
            int serviceIdx = fullName.IndexOf("._", StringComparison.Ordinal);
            if (serviceIdx > 0)
            {
                fullName = fullName.Substring(0, serviceIdx);
            }

            // Remove ".local" suffix
            if (fullName.EndsWith(".local", StringComparison.OrdinalIgnoreCase))
            {
                fullName = fullName.Substring(0, fullName.Length - 6);
            }

            return fullName.Length > 0 ? fullName : null;
        }

        // ──────────────────────────────────────────────
        //  Layer 5: Device type heuristic
        // ──────────────────────────────────────────────

        public static DeviceType InferDeviceType(PC device)
        {
            if (device.IsGateway) return DeviceType.Router;

            string vendor = device.Vendor ?? string.Empty;
            string hostname = device.Hostname ?? string.Empty;

            // Check hostname keywords first (more specific)
            if (ContainsAny(hostname, "iPhone", "iPad", "Galaxy", "Redmi", "POCO", "Pixel"))
                return DeviceType.Mobile;

            if (ContainsAny(hostname, "MacBook", "iMac", "DESKTOP-", "LAPTOP-", "Surface"))
                return DeviceType.Desktop;

            if (ContainsAny(hostname, "-TV", "SmartTV", "BRAVIA", "Roku", "Fire-TV", "Chromecast"))
                return DeviceType.SmartTV;

            if (ContainsAny(hostname, "PlayStation", "Xbox", "Switch"))
                return DeviceType.Console;

            if (ContainsAny(hostname, "printer", "LaserJet", "DeskJet", "EPSON", "Canon"))
                return DeviceType.Printer;

            // Check vendor keywords
            if (ContainsAny(vendor, "Nintendo"))
                return DeviceType.Console;

            if (ContainsAny(vendor, "Sony Interactive"))
                return DeviceType.Console;

            if (ContainsAny(vendor, "Roku"))
                return DeviceType.SmartTV;

            if (ContainsAny(vendor, "LG Electronics") && ContainsAny(hostname, "TV", "webOS"))
                return DeviceType.SmartTV;

            if (ContainsAny(vendor, "Sonos"))
                return DeviceType.IoT;

            if (ContainsAny(vendor, "Espressif", "Tuya", "Raspberry Pi"))
                return DeviceType.IoT;

            if (ContainsAny(vendor, "Ubiquiti", "Cisco", "NETGEAR", "TP-Link", "D-Link",
                            "Arris", "ZTE", "Sagemcom", "Aruba", "Arcadyan", "Technicolor",
                            "Zhone/DZS", "Dasan", "CIG/Shanghai Bell"))
                return DeviceType.NetworkInfra;

            if (ContainsAny(vendor, "Zengge", "LED"))
                return DeviceType.IoT;

            if (ContainsAny(vendor, "HP", "Epson", "Canon") && !ContainsAny(hostname, "DESKTOP", "LAPTOP"))
                return DeviceType.Printer;

            if (ContainsAny(vendor, "Apple"))
                return DeviceType.Mobile; // Default Apple to mobile (most common)

            if (ContainsAny(vendor, "Samsung", "Xiaomi", "Huawei", "OnePlus", "OPPO", "Vivo"))
                return DeviceType.Mobile;

            if (ContainsAny(vendor, "Intel", "Realtek", "Dell", "Lenovo", "Microsoft"))
                return DeviceType.Desktop;

            if (ContainsAny(vendor, "Amazon"))
                return DeviceType.IoT;

            if (ContainsAny(vendor, "Google"))
                return DeviceType.IoT;

            return DeviceType.Unknown;
        }

        private static bool ContainsAny(string text, params string[] keywords)
        {
            foreach (var kw in keywords)
            {
                if (text.Contains(kw, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        public void Dispose()
        {
            StopMdnsListener();
            _hostnameCache.Clear();
        }
    }
}

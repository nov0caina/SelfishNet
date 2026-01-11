using System;
using System.Net;
using System.Net.NetworkInformation;

namespace SelfishNetV4
{
    public class PC
    {
        public string IP_String { get { return ip?.ToString() ?? "..."; } }
        public string MAC_String { get { return mac?.ToString() ?? "..."; } }
        
        public bool Redirect { get; set; } = false;
        public bool Block { get; set; } = false;

        public IPAddress ip { get; set; }
        public PhysicalAddress mac { get; set; }
        public string name { get; set; } = "Unknown";
        
        public bool isGateway { get; set; }
        public bool isLocalPc { get; set; }

        public DateTime timeSinceLastRarp { get; set; }
        
        public int nbPacketSentSinceLastReset;
        public int nbPacketReceivedSinceLastReset;
    }
}
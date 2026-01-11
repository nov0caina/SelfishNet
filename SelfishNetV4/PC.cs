using System;
using System.Net;
using System.Net.NetworkInformation;

namespace SelfishNetV4
{
#pragma warning disable
    public class PC

    {
        public IPAddress ip;

        public PhysicalAddress mac;

        public string name;

        public bool isGateway;

        public bool isLocalPc;

        public int capDown;

        public int capUp;

        public bool redirect;

        public int totalPacketSent;

        public int totalPacketReceived;

        public int nbPacketSentSinceLastReset;

        public int nbPacketReceivedSinceLastReset;

        public ValueType timeSinceLastRarp;
    }
#pragma warning restore
}

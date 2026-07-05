using System;
using System.Net;

namespace SelfishNet
{
    public static class Tools
    {
        public static IPAddress ParseIpAddress(string ip)
        {
            string[] parts = ip.Split('.');
            byte[] bytes = new byte[4];
            for (int i = 0; i < 4; i++)
            {
                bytes[i] = Convert.ToByte(parts[i]);
            }
            return new IPAddress(bytes);
        }

        public static bool AreValuesEqual(byte[] a, byte[] b)
        {
            return a != null && b != null && a.AsSpan().SequenceEqual(b);
        }
    }
}

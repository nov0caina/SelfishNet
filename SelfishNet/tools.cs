using System;
using System.Net;
using System.Runtime.InteropServices;

namespace SelfishNet 
{
#pragma warning disable
    public class tools

    {
        public static IPAddress getIpAddress(string ip)
        {
            string[] array3 = new string[4];
            byte[] array = new byte[4];
            string[] array2 = ip.Split('.', '\u0003');
            int num = 0;
            do
            {
                array[num] = Convert.ToByte(array2[num]);
                num++;
            }
            while (num < 4);
            return new IPAddress(array);
        }

        [return: MarshalAs(UnmanagedType.U1)]
        public unsafe static bool areValuesEqual(byte[] obj1, byte[] obj2)
        {
            if (obj1 != null && obj2 != null)
            {
                int num = obj1.Length;
                if ((IntPtr)num != (IntPtr)(void*)obj2.LongLength)
                {
                    return false;
                }
                int num2 = 0;
                int num3 = num;
                if (0 < num3)
                {
                    do
                    {
                        if (obj1[num2] == obj2[num2])
                        {
                            num2++;
                            continue;
                        }
                        return false;
                    }
                    while (num2 < num3);
                }
                return true;
            }
            return false;
        }
    }
#pragma warning restore
}

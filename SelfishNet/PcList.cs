using System;
using System.Collections;
using System.Runtime.InteropServices;
using System.Threading;

namespace SelfishNet
{
    public delegate void delegateOnNewPC(PC pc);
#pragma warning disable
    public class PcList : IDisposable

    {
        private delegateOnNewPC delOnNewPC;

        private delegateOnNewPC delOnPCRemove;

        public ArrayList pclist;

        public PcList()
        {
            pclist = new ArrayList();
        }

        [return: MarshalAs(UnmanagedType.U1)]
        public bool addPcToList(PC pc)
        {
            Monitor.Enter(pclist.SyncRoot);
            foreach (PC item in pclist)
            {
                if (item.ip.ToString().CompareTo(pc.ip.ToString()) == 0)
                {
                    DateTime now = DateTime.Now;
                    item.timeSinceLastRarp = now;
                    Monitor.Exit(pclist.SyncRoot);
                    return false;
                }
            }
            ArrayList.Synchronized(pclist).Add(pc);

            if (delOnNewPC != null)
            {
                delOnNewPC.Invoke(pc);
            }

            Monitor.Exit(pclist.SyncRoot);
            return true;
        }

        [return: MarshalAs(UnmanagedType.U1)]
        public bool removePcFromList(PC pc)
        {
            Monitor.Enter(pclist.SyncRoot);
            foreach (PC item in pclist)
            {
                if (item.ip.ToString().CompareTo(pc.ip.ToString()) == 0)
                {
                    if (delOnPCRemove != null)
                    {
                        delOnPCRemove.Invoke(pc);
                    }

                    pclist.Remove(pc);
                    Monitor.Exit(pclist.SyncRoot);
                    return true;
                }
            }
            Monitor.Exit(pclist.SyncRoot);
            return false;
        }

        public PC getRouter()
        {
            Monitor.Enter(pclist.SyncRoot);
            IEnumerator enumerator = pclist.GetEnumerator();
            if (enumerator.MoveNext())
            {
                do
                {
                    if (((PC)enumerator.Current).isGateway)
                    {
                        Monitor.Exit(pclist.SyncRoot);
                        return (PC)enumerator.Current;
                    }
                }
                while (enumerator.MoveNext());
            }
            Monitor.Exit(pclist.SyncRoot);
            return null;
        }

        public PC getLocalPC()
        {
            Monitor.Enter(pclist.SyncRoot);
            IEnumerator enumerator = pclist.GetEnumerator();
            if (enumerator.MoveNext())
            {
                do
                {
                    if (((PC)enumerator.Current).isLocalPc)
                    {
                        Monitor.Exit(pclist.SyncRoot);
                        return (PC)enumerator.Current;
                    }
                }
                while (enumerator.MoveNext());
            }
            Monitor.Exit(pclist.SyncRoot);
            return null;
        }

        public PC getPCFromIP(byte[] ip)
        {
            Monitor.Enter(pclist.SyncRoot);
            IEnumerator enumerator = pclist.GetEnumerator();
            if (enumerator.MoveNext())
            {
                do
                {
                    if (tools.areValuesEqual(((PC)enumerator.Current).ip.GetAddressBytes(), ip))
                    {
                        Monitor.Exit(pclist.SyncRoot);
                        return (PC)enumerator.Current;
                    }
                }
                while (enumerator.MoveNext());
            }
            Monitor.Exit(pclist.SyncRoot);
            return null;
        }

        public PC getPCFromMac(byte[] Mac)
        {
            Monitor.Enter(pclist.SyncRoot);
            IEnumerator enumerator = pclist.GetEnumerator();
            if (enumerator.MoveNext())
            {
                do
                {
                    if (tools.areValuesEqual(((PC)enumerator.Current).mac.GetAddressBytes(), Mac))
                    {
                        Monitor.Exit(pclist.SyncRoot);
                        return (PC)enumerator.Current;
                    }
                }
                while (enumerator.MoveNext());
            }
            Monitor.Exit(pclist.SyncRoot);
            return null;
        }

        public void ResetAllPacketsCount()
        {
            Monitor.Enter(pclist.SyncRoot);
            IEnumerator enumerator = pclist.GetEnumerator();
            if (enumerator.MoveNext())
            {
                do
                {
                    ((PC)enumerator.Current).nbPacketReceivedSinceLastReset = 0;
                    ((PC)enumerator.Current).nbPacketSentSinceLastReset = 0;
                }
                while (enumerator.MoveNext());
            }
            Monitor.Exit(pclist.SyncRoot);
        }

        public void SetCallBackOnNewPC(delegateOnNewPC callback)
        {
            delOnNewPC = callback;
        }

        public void SetCallBackOnPCRemove(delegateOnNewPC callback)
        {
            delOnPCRemove = callback;
        }

        public void Clear()
        {
            Monitor.Enter(pclist.SyncRoot);
            pclist.Clear();
            Monitor.Exit(pclist.SyncRoot);
        }

        public void Dispose()
        {

            GC.SuppressFinalize(this);
        }
    }
#pragma warning restore  
}

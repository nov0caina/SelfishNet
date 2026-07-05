using System;
using System.Collections.Generic;

namespace SelfishNet
{
    /// <summary>Callback when a device is detected or removed.</summary>
    public delegate void OnDeviceEvent(PC pc);

    public class PcList : IDisposable
    {
        private OnDeviceEvent _onDeviceAdded;
        private OnDeviceEvent _onDeviceRemoved;

        private readonly object _syncLock = new();
        private readonly List<PC> _devices = new();

        /// <summary>
        /// Returns a thread-safe snapshot (array copy) for external iteration.
        /// </summary>
        public IReadOnlyList<PC> Devices
        {
            get
            {
                lock (_syncLock)
                {
                    return _devices.ToArray();
                }
            }
        }

        public bool AddDevice(PC pc)
        {
            lock (_syncLock)
            {
                foreach (PC item in _devices)
                {
                    if (item.Ip.ToString().CompareTo(pc.Ip.ToString()) == 0)
                    {
                        item.TimeSinceLastArp = DateTime.Now;
                        return false;
                    }
                }
                _devices.Add(pc);
            }

            // Invoke callback outside lock to prevent UI thread deadlocks
            _onDeviceAdded?.Invoke(pc);
            return true;
        }

        public bool RemoveDevice(PC pc)
        {
            PC found = null;
            lock (_syncLock)
            {
                for (int i = 0; i < _devices.Count; i++)
                {
                    if (_devices[i].Ip.ToString().CompareTo(pc.Ip.ToString()) == 0)
                    {
                        found = _devices[i];
                        _devices.RemoveAt(i);
                        break;
                    }
                }
            }

            if (found != null)
            {
                _onDeviceRemoved?.Invoke(pc);
                return true;
            }
            return false;
        }

        public PC GetRouter()
        {
            lock (_syncLock)
            {
                foreach (PC item in _devices)
                {
                    if (item.IsGateway) return item;
                }
            }
            return null;
        }

        public PC GetLocalPC()
        {
            lock (_syncLock)
            {
                foreach (PC item in _devices)
                {
                    if (item.IsLocalPc) return item;
                }
            }
            return null;
        }

        public PC GetDeviceByIp(byte[] ip)
        {
            lock (_syncLock)
            {
                foreach (PC item in _devices)
                {
                    if (Tools.AreValuesEqual(item.Ip.GetAddressBytes(), ip))
                        return item;
                }
            }
            return null;
        }

        public PC GetDeviceByMac(byte[] mac)
        {
            lock (_syncLock)
            {
                foreach (PC item in _devices)
                {
                    if (Tools.AreValuesEqual(item.Mac.GetAddressBytes(), mac))
                        return item;
                }
            }
            return null;
        }

        public void ResetAllPacketCounts()
        {
            lock (_syncLock)
            {
                foreach (PC item in _devices)
                {
                    item.BytesReceived = 0;
                    item.BytesSent = 0;
                }
            }
        }

        public void SetOnDeviceAdded(OnDeviceEvent callback)
        {
            _onDeviceAdded = callback;
        }

        public void SetOnDeviceRemoved(OnDeviceEvent callback)
        {
            _onDeviceRemoved = callback;
        }

        public void Clear()
        {
            lock (_syncLock)
            {
                _devices.Clear();
            }
        }

        public void Dispose()
        {
            Clear();
            GC.SuppressFinalize(this);
        }
    }
}

using System;
using System.ComponentModel;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.CompilerServices;

namespace SelfishNet
{
    public class PC : INotifyPropertyChanged
    {
        // ── Display properties (XAML bindings) ──

        public string IpDisplay => Ip?.ToString() ?? "...";
        public string MacDisplay => Mac?.ToString() ?? "...";

        // ── Core network properties ──

        public IPAddress Ip { get; set; }
        public PhysicalAddress Mac { get; set; }
        public string Name { get; set; } = "Unknown";

        // ── State flags ──

        public bool Redirect { get; set; } = false;
        public bool Block { get; set; } = false;
        public bool IsGateway { get; set; }
        public bool IsLocalPc { get; set; }

        // ── Tracking ──

        public DateTime TimeSinceLastArp { get; set; }

        /// <summary>Bytes sent in current monitoring cycle.</summary>
        public int BytesSent;

        /// <summary>Bytes received in current monitoring cycle.</summary>
        public int BytesReceived;

        // ── Bindable download speed ──

        private string _downloadSpeed = "—";
        public string DownloadSpeed
        {
            get => _downloadSpeed;
            set
            {
                if (_downloadSpeed != value)
                {
                    _downloadSpeed = value;
                    OnPropertyChanged();
                }
            }
        }

        // ── INotifyPropertyChanged ──

        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
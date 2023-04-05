using System.Net.Security;
using System.Net.Sockets;

namespace EasyTCPeasy.Network.Server
{
    public class EasyTCPClient
    {
        public TcpClient Client { get; init; }
        public bool SslEnabled { get; init; }

        private SslStream _sslStream;

        public Stream GetStream()
        {
            if(SslEnabled)
            {
                if(_sslStream == null)
                {
                    _sslStream = new SslStream(Client.GetStream(), leaveInnerStreamOpen: false);
                }

                return _sslStream;
            }
            else
            {
                return Client.GetStream();
            }
        }
    }
}

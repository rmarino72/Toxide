using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace Toxide.Network;

/// <summary>
/// The UDP socket shared by all Tox components (DHT, onion, net_crypto all use the same port).
///  - Binds the first free port in a range (toxcore default: 33445-33545).
///  - Dual-stack when possible: a single IPv6 socket that also talks to IPv4 peers.
///  - A background loop receives datagrams and queues them in <see cref="Incoming"/>;
///    the queue is bounded and drops new packets when full, as an overloaded kernel buffer would.
///  - Implements <see cref="IPacketSender"/> with a synchronous send: UDP sends do not block, and
///    protocol code running on the event loop must not await.
/// </summary>
public sealed class UdpTransport : IPacketSender, IAsyncDisposable
{
    public const int MaxPacketSize = 2048;
    public const ushort DefaultPortStart = 33445;
    public const ushort DefaultPortEnd = 33545;

    // Windows: stop ICMP "port unreachable" from surfacing as ConnectionReset on later receives.
    private const int SioUdpConnReset = unchecked((int)0x9800000C);

    private readonly Socket _socket;
    private readonly Channel<ReceivedPacket> _incoming;
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _receiveLoop;

    public ushort LocalPort { get; }
    public bool IsDualStack { get; }
    public ChannelReader<ReceivedPacket> Incoming => _incoming.Reader;

    private UdpTransport(Socket socket, int queueCapacity)
    {
        _socket = socket;
        LocalPort = (ushort)((IPEndPoint)socket.LocalEndPoint!).Port;
        IsDualStack = socket.AddressFamily == AddressFamily.InterNetworkV6 && socket.DualMode;

        _incoming = Channel.CreateBounded<ReceivedPacket>(new BoundedChannelOptions(queueCapacity)
        {
            FullMode = BoundedChannelFullMode.DropWrite,
            SingleReader = true,
            SingleWriter = true,
        });

        _receiveLoop = Task.Run(ReceiveLoopAsync);
    }

    /// <summary>
    /// Binds the first available port in [portStart, portEnd]. Use 0, 0 to let the OS choose.
    /// With <paramref name="ipv6"/> false the socket is IPv4-only.
    /// </summary>
    public static UdpTransport Bind(ushort portStart = DefaultPortStart, ushort portEnd = DefaultPortEnd,
        int queueCapacity = 1024, bool ipv6 = true)
    {
        if (portEnd < portStart)
            throw new ArgumentException("portEnd must be >= portStart.", nameof(portEnd));

        for (int port = portStart; port <= portEnd; port++)
        {
            var socket = CreateSocket(ipv6);
            try
            {
                var any = socket.AddressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any;
                socket.Bind(new IPEndPoint(any, port));
                return new UdpTransport(socket, queueCapacity);
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse)
            {
                socket.Dispose(); // port taken (e.g. another Tox client): try the next one
            }
        }

        throw new SocketException((int)SocketError.AddressAlreadyInUse);
    }

    /// <summary>
    /// Sends one datagram. UDP gives no delivery guarantee: true only means the OS accepted it.
    /// Returns false if the destination is unreachable from this socket (e.g. IPv6 on an IPv4-only host).
    /// </summary>
    public async ValueTask<bool> SendAsync(IpPort destination, ReadOnlyMemory<byte> packet,
        CancellationToken cancellationToken = default)
    {
        if (packet.Length is 0 or > MaxPacketSize)
            throw new ArgumentException($"Packet size must be 1-{MaxPacketSize} bytes.", nameof(packet));

        if (!destination.IsIPv4 && _socket.AddressFamily == AddressFamily.InterNetwork)
            return false;

        try
        {
            await _socket.SendToAsync(packet, SocketFlags.None, destination.ToEndPoint(), cancellationToken);
            return true;
        }
        catch (SocketException)
        {
            return false;
        }
    }

    public bool CanReach(IpPort destination) =>
        destination.IsIPv4 || _socket.AddressFamily == AddressFamily.InterNetworkV6;

    public bool Send(IpPort destination, ReadOnlySpan<byte> packet)
    {
        if (packet.Length is 0 or > MaxPacketSize || !CanReach(destination))
            return false;

        try
        {
            return _socket.SendTo(packet, SocketFlags.None, destination.ToEndPoint()) == packet.Length;
        }
        catch (SocketException)
        {
            return false; // e.g. network unreachable, broadcast not permitted
        }
        catch (ObjectDisposedException)
        {
            return false;
        }
    }

    private async Task ReceiveLoopAsync()
    {
        var buffer = new byte[MaxPacketSize];
        EndPoint anyRemote = _socket.AddressFamily == AddressFamily.InterNetworkV6
            ? new IPEndPoint(IPAddress.IPv6Any, 0)
            : new IPEndPoint(IPAddress.Any, 0);

        while (!_cts.IsCancellationRequested)
        {
            SocketReceiveFromResult result;
            try
            {
                result = await _socket.ReceiveFromAsync(buffer, SocketFlags.None, anyRemote, _cts.Token);
            }
            catch (OperationCanceledException) { break; }
            catch (ObjectDisposedException) { break; }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset
                                                 or SocketError.MessageSize)
            {
                continue; // ICMP noise or oversized datagram: ignore and keep listening
            }

            if (result.ReceivedBytes == 0)
                continue;

            var source = IpPort.FromEndPoint((IPEndPoint)result.RemoteEndPoint);
            var data = buffer.AsSpan(0, result.ReceivedBytes).ToArray();
            _incoming.Writer.TryWrite(new ReceivedPacket(source, data)); // false = queue full = dropped
        }

        _incoming.Writer.TryComplete();
    }

    private static Socket CreateSocket(bool ipv6)
    {
        Socket socket;
        if (ipv6 && Socket.OSSupportsIPv6)
        {
            socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
            try { socket.DualMode = true; }
            catch (SocketException)
            {
                socket.Dispose();
                socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            }
        }
        else
        {
            socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        }

        if (OperatingSystem.IsWindows())
            socket.IOControl(SioUdpConnReset, new byte[4], null);

        // Needed for LAN discovery; some stacks refuse it on IPv6 sockets, which only disables that feature.
        try { socket.EnableBroadcast = true; }
        catch (SocketException) { }

        return socket;
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        _socket.Dispose();
        try { await _receiveLoop; } catch { /* loop is shutting down */ }
        _incoming.Writer.TryComplete();
        _cts.Dispose();
    }
}
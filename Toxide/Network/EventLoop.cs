using System.Threading.Channels;

namespace Toxide.Network;

/// <summary>
/// The single thread on which all protocol logic runs (toxcore's tox_iterate, as a loop).
/// Each iteration: dispatch every queued packet, run the periodic tasks ("tickers"),
/// then sleep until a new packet arrives or the tick interval elapses.
/// </summary>
public sealed class EventLoop
{
    public static readonly TimeSpan DefaultTickInterval = TimeSpan.FromMilliseconds(50);

    private readonly ChannelReader<ReceivedPacket> _incoming;
    private readonly PacketDispatcher _dispatcher;
    private readonly TimeSpan _tickInterval;
    private readonly List<Action> _tickers = [];

    /// <summary>Raised when a handler or ticker throws: a bad packet must never stop the node.</summary>
    public event Action<Exception>? Error;

    public EventLoop(ChannelReader<ReceivedPacket> incoming, PacketDispatcher dispatcher, TimeSpan? tickInterval = null)
    {
        _incoming = incoming;
        _dispatcher = dispatcher;
        _tickInterval = tickInterval ?? DefaultTickInterval;
    }

    public void AddTicker(Action tick) => _tickers.Add(tick);

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            while (_incoming.TryRead(out var packet))
                Guard(() => _dispatcher.Dispatch(packet.Source, packet.Data));

            foreach (var tick in _tickers)
                Guard(tick);

            using var wait = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            wait.CancelAfter(_tickInterval);
            try
            {
                if (!await _incoming.WaitToReadAsync(wait.Token).ConfigureAwait(false))
                    return; // transport closed
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // tick interval elapsed: loop again
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    private void Guard(Action action)
    {
        try { action(); }
        catch (Exception ex) { Error?.Invoke(ex); }
    }
}
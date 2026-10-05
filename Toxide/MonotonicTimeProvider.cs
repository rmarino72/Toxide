namespace Toxide;

/// <summary>
/// Wall-clock time at start-up plus elapsed monotonic time: timestamps look like UTC (cookies,
/// DHT key announcements carry them) but never step backwards or jump with clock changes.
/// </summary>
internal sealed class MonotonicTimeProvider : TimeProvider
{
    private readonly DateTimeOffset _start = System.GetUtcNow();
    private readonly long _startTimestamp = System.GetTimestamp();

    public override DateTimeOffset GetUtcNow() => _start + System.GetElapsedTime(_startTimestamp);
}

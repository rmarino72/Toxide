namespace Tests.Infrastructure;

/// <summary>A clock that only moves when told to: protocol timers become deterministic and fast.</summary>
public sealed class ManualTimeProvider : TimeProvider
{
    private DateTimeOffset _now;

    public ManualTimeProvider(DateTimeOffset? start = null) =>
        _now = start ?? new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan delta) => _now += delta;
}

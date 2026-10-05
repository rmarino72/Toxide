using System.Collections.Concurrent;
using System.Diagnostics;

namespace Tests.Interop;

/// <summary>Runs only when TOXIDE_TOXPEER points to the toxcore test peer (see Tests/Interop/README.md).</summary>
public sealed class ToxcoreFactAttribute : FactAttribute
{
    public ToxcoreFactAttribute()
    {
        if (ToxPeer.ExecutablePath is null)
            Skip = "Set TOXIDE_TOXPEER to the toxpeer executable built against c-toxcore.";
    }
}

/// <summary>A toxcore instance in a child process, driven through a line protocol on stdin/stdout.</summary>
public sealed class ToxPeer : IDisposable
{
    private readonly Process _process;
    private readonly BlockingCollection<string> _lines = new();
    private readonly List<string> _history = [];

    public static string? ExecutablePath =>
        Environment.GetEnvironmentVariable("TOXIDE_TOXPEER") is { } p && File.Exists(p) ? p : null;

    private ToxPeer(Process process) => _process = process;

    public string Address { get; private set; } = "";
    public string DhtId { get; private set; } = "";
    public ushort Port { get; private set; }
    public string PublicKey => Address[..64];

    public static ToxPeer Start(ushort port, string? saveFile = null, string? passphrase = null)
    {
        var psi = new ProcessStartInfo(ExecutablePath!)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = false,
            UseShellExecute = false,
        };
        psi.ArgumentList.Add(port.ToString());
        if (saveFile is not null)
            psi.ArgumentList.Add(saveFile);
        if (passphrase is not null)
            psi.ArgumentList.Add(passphrase);

        var peer = new ToxPeer(Process.Start(psi)!);
        peer._process.OutputDataReceived += (_, e) =>
        {
            if (e.Data is not null)
                peer._lines.Add(e.Data);
        };
        peer._process.BeginOutputReadLine();

        var ready = peer.WaitFor(l => l.StartsWith("READY "), TimeSpan.FromSeconds(30)).Split(' ');
        peer.Address = ready[1];
        peer.DhtId = ready[2];
        peer.Port = ushort.Parse(ready[3]);
        return peer;
    }

    public void Send(string command)
    {
        _process.StandardInput.WriteLine(command);
        _process.StandardInput.Flush();
    }

    /// <summary>Waits for an output line matching <paramref name="match"/>; earlier lines are kept for later waits.</summary>
    public string WaitFor(Func<string, bool> match, TimeSpan timeout)
    {
        lock (_history)
        {
            var seen = _history.FirstOrDefault(match);
            if (seen is not null)
            {
                _history.Remove(seen);
                return seen;
            }
        }

        var deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (!_lines.TryTake(out var line, TimeSpan.FromMilliseconds(100)))
                continue;
            if (match(line))
                return line;
            lock (_history)
                _history.Add(line);
        }

        string seenLines;
        lock (_history)
            seenLines = string.Join(" | ", _history);
        throw new TimeoutException($"toxpeer:{Port} did not print the expected line. Output so far: {seenLines}");
    }

    public void Dispose()
    {
        try
        {
            Send("QUIT");
            if (!_process.WaitForExit(3000))
                _process.Kill();
        }
        catch (Exception)
        {
            // already gone
        }
        _process.Dispose();
    }
}

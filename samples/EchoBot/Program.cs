// A Tox echo bot: accepts every friend request and sends every message back.
// Usage: dotnet run --project samples/EchoBot [profile.tox]
using System.Text.Json;
using Toxide;

string profilePath = args.Length > 0 ? args[0] : "echobot.tox";

var options = new ToxOptions();
if (File.Exists(profilePath))
{
    options.SaveDataType = ToxSaveDataType.ToxSave;
    options.SaveData = File.ReadAllBytes(profilePath);
}

using var tox = Tox.Create(options);
tox.Name = "Toxide Echo Bot";
tox.StatusMessage = "I repeat everything you say";

tox.ConnectionStatusChanged += (_, e) => Console.WriteLine($"Network: {e.Connection}");
tox.FriendRequestReceived += (_, e) =>
{
    Console.WriteLine($"Friend request from {Convert.ToHexString(e.PublicKey)}: {e.Message}");
    tox.AddFriendNoRequest(e.PublicKey);
    File.WriteAllBytes(profilePath, tox.GetSaveData());
};
tox.FriendConnectionStatusChanged += (_, e) =>
    Console.WriteLine($"{tox.GetFriendName(e.FriendNumber)} is now {(e.Connection == ToxConnection.None ? "offline" : "online")}");
tox.FriendMessageReceived += (_, e) =>
{
    Console.WriteLine($"{tox.GetFriendName(e.FriendNumber)}: {e.Message}");
    tox.SendMessage(e.FriendNumber, e.Message, e.Type);
};
tox.FileReceiveRequested += (_, e) => tox.FileControl(e.FriendNumber, e.FileNumber, ToxFileControl.Cancel);

// Join the network through the public bootstrap nodes listed on nodes.tox.chat.
using (var http = new HttpClient())
{
    var list = JsonDocument.Parse(await http.GetStringAsync("https://nodes.tox.chat/json"));
    foreach (var node in list.RootElement.GetProperty("nodes").EnumerateArray())
    {
        if (!node.GetProperty("status_udp").GetBoolean())
            continue;
        try
        {
            tox.Bootstrap(node.GetProperty("ipv4").GetString()!, node.GetProperty("port").GetUInt16(),
                node.GetProperty("public_key").GetString()!);
        }
        catch (ToxException)
        {
            // unresolvable host or malformed entry: skip it
        }
    }
}

File.WriteAllBytes(profilePath, tox.GetSaveData());
Console.WriteLine($"Tox ID: {tox.Address}");
Console.WriteLine("Press Ctrl+C to quit.");

using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};
await tox.RunAsync(cts.Token);
File.WriteAllBytes(profilePath, tox.GetSaveData());

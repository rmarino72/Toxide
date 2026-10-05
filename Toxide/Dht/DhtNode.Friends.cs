using Toxide.Crypto;
using Toxide.Network;

namespace Toxide.Dht;

/// <summary>
/// Friend search: how we learn the IP address of a friend.
///
/// Our friends' DHT keys reach us through the onion (DHT key announcements). For each such key we
/// run a continuous lookup, keeping the 8 nodes closest to it. Those nodes have the friend in their
/// own lists, so in their nodes responses they report the address at which they see the friend.
/// We then contact the friend at that address; when it answers, its address is verified.
///
/// The nodes that reported the friend's address also serve as relays for crypto requests (0x20)
/// when we cannot reach the friend directly, e.g. for NAT hole punching.
/// </summary>
public sealed partial class DhtNode
{
    private const int MaxBootstrapTimes = 5;
    private const int MinRelaysToRoute = DhtFriend.MaxCloseNodes / 4;

    private readonly Dictionary<byte[], DhtFriend> _friends = new(PublicKeyComparer.Instance);

    internal int FriendCount => _friends.Count;

    /// <summary>
    /// Starts searching for a DHT key; <paramref name="onEndpointFound"/> runs every time the
    /// friend's address is confirmed. Several components may search the same key.
    /// </summary>
    internal void AddFriend(byte[] dhtPublicKey, Action<IpPort> onEndpointFound)
    {
        if (!_friends.TryGetValue(dhtPublicKey, out var friend))
        {
            friend = new DhtFriend((byte[])dhtPublicKey.Clone(), RandomUInt64());
            _friends[friend.PublicKey] = friend;

            // Kick off the lookup with the nodes we already know closest to that key.
            foreach (var node in FindClosest(dhtPublicKey, DhtPayloads.MaxNodes))
                SendNodesRequest(node, friend.PublicKey);
            friend.LastNodesRequest = Now;
        }

        friend.AddCallback(onEndpointFound);
    }

    internal void RemoveFriend(byte[] dhtPublicKey, Action<IpPort> onEndpointFound)
    {
        if (!_friends.TryGetValue(dhtPublicKey, out var friend))
            return;

        friend.RemoveCallback(onEndpointFound);
        if (friend.IsUnused)
            _friends.Remove(dhtPublicKey);
    }

    /// <summary>The friend's address, if the friend has answered us recently.</summary>
    internal bool TryGetFriendEndpoint(byte[] dhtPublicKey, out IpPort endpoint)
    {
        endpoint = default;
        if (!_friends.TryGetValue(dhtPublicKey, out var friend) || !friend.HasDirectConnection(Now, BadNodeTimeout))
            return false;

        endpoint = friend.DirectEndpoint!.Value;
        return true;
    }

    /// <summary>
    /// Sends <paramref name="packet"/> to every node that reported the friend's address
    /// (toxcore's route_to_friend). Returns the number of nodes it was sent to; 0 when we are
    /// directly connected (there is no need) or too few nodes know the friend.
    /// </summary>
    internal int RouteToFriend(byte[] dhtPublicKey, ReadOnlySpan<byte> packet)
    {
        if (!_friends.TryGetValue(dhtPublicKey, out var friend) || friend.HasDirectConnection(Now, BadNodeTimeout))
            return 0;

        var relays = friend.FreshReturned(Now, BadNodeTimeout);
        if (relays.Count < MinRelaysToRoute)
            return 0;

        int sent = 0;
        foreach (var relay in relays)
            if (_sender.Send(relay.Relay.Endpoint, packet))
                sent++;
        return sent;
    }

    /// <summary>Like <see cref="RouteToFriend"/>, through one random node only.</summary>
    internal int RouteOneToFriend(byte[] dhtPublicKey, ReadOnlySpan<byte> packet)
    {
        if (!_friends.TryGetValue(dhtPublicKey, out var friend))
            return 0;

        var relays = friend.FreshReturned(Now, BadNodeTimeout);
        if (relays.Count == 0)
            return 0;

        return _sender.Send(relays[Random.Shared.Next(relays.Count)].Relay.Endpoint, packet) ? 1 : 0;
    }

    /// <summary>A node answered us: it may belong among a friend's close nodes, or be the friend itself.</summary>
    private void OfferToFriends(NodeInfo node, DateTimeOffset now)
    {
        foreach (var friend in _friends.Values)
        {
            if (!friend.WouldStore(node.PublicKey, now, BadNodeTimeout)
                && !friend.CloseNodes.Exists(e => e.Node.PublicKey.AsSpan().SequenceEqual(node.PublicKey)))
                continue;

            friend.AddOrUpdate(node, now, BadNodeTimeout);

            if (node.PublicKey.AsSpan().SequenceEqual(friend.PublicKey))
            {
                friend.DirectEndpoint = node.Endpoint;
                friend.DirectSeen = now;
                foreach (var callback in friend.Callbacks.ToList())
                    callback(node.Endpoint);
            }
        }
    }

    /// <summary>A node listed in a nodes response from <paramref name="responder"/>.</summary>
    private void OnReturnedNode(NodeInfo responder, NodeInfo node)
    {
        // Like toxcore's returnedip_ports, only nodes among the friend's close nodes count: random
        // (or malicious) responders must not steer routing and hole punching.
        if (_friends.TryGetValue(node.PublicKey, out var friend)
            && friend.CloseNodes.Exists(e => e.Node.PublicKey.AsSpan().SequenceEqual(responder.PublicKey)))
            friend.AddReturned(responder, node.Endpoint, Now);
    }

    /// <summary>Asks <paramref name="node"/> about a friend if it would be one of that friend's close nodes.</summary>
    private bool TryFriendLookup(NodeInfo node)
    {
        var now = Now;
        foreach (var friend in _friends.Values)
        {
            if (friend.CloseNodes.Exists(e => e.Node.PublicKey.AsSpan().SequenceEqual(node.PublicKey)))
                continue;
            if (!friend.WouldStore(node.PublicKey, now, BadNodeTimeout))
                continue;

            SendNodesRequest(node, friend.PublicKey);
            return true;
        }
        return false;
    }

    /// <summary>Nodes responses also include friends' close nodes, as toxcore's get_close_nodes does.</summary>
    private void AddDirectFriendsTo(List<NodeInfo> closest, byte[] target, byte[] requesterKey, IpPort requester)
    {
        if (_friends.Count == 0)
            return;

        var now = Now;
        foreach (var friend in _friends.Values)
        {
            foreach (var entry in friend.CloseNodes)
            {
                var node = entry.Node;
                if (entry.IsBad(now, BadNodeTimeout) || node.PublicKey.AsSpan().SequenceEqual(requesterKey))
                    continue;
                if (!requester.IsLan() && node.Endpoint.IsLan())
                    continue; // don't send LAN addresses to Internet peers
                if (closest.Exists(n => n.PublicKey.AsSpan().SequenceEqual(node.PublicKey)))
                    continue;
                closest.Add(node);
            }
        }

        closest.Sort((a, b) => XorDistance.Compare(target, a.PublicKey, b.PublicKey));
        if (closest.Count > DhtPayloads.MaxNodes)
            closest.RemoveRange(DhtPayloads.MaxNodes, closest.Count - DhtPayloads.MaxNodes);
    }

    /// <summary>Once per second: keep every friend lookup alive.</summary>
    private void TickFriends(DateTimeOffset now)
    {
        foreach (var friend in _friends.Values)
        {
            friend.CloseNodes.RemoveAll(e => e.IsBad(now, BadNodeTimeout));
            if (friend.DirectEndpoint is not null && !friend.HasDirectConnection(now, BadNodeTimeout))
                friend.DirectEndpoint = null;

            foreach (var entry in friend.CloseNodes)
            {
                if (now - entry.LastPinged >= PingInterval)
                {
                    entry.LastPinged = now;
                    SendNodesRequest(entry.Node, friend.PublicKey);
                }
            }

            if (now - friend.LastNodesRequest < NodesRequestInterval && friend.BootstrapTimes >= MaxBootstrapTimes)
                continue;

            friend.LastNodesRequest = now;
            friend.BootstrapTimes++;
            if (friend.CloseNodes.Count > 0)
            {
                var entry = friend.CloseNodes[Random.Shared.Next(friend.CloseNodes.Count)];
                SendNodesRequest(entry.Node, friend.PublicKey);
            }
            else
            {
                foreach (var node in FindClosest(friend.PublicKey, DhtPayloads.MaxNodes))
                    SendNodesRequest(node, friend.PublicKey);
            }
        }
    }

    private static ulong RandomUInt64()
    {
        Span<byte> bytes = stackalloc byte[8];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bytes);
        return BitConverter.ToUInt64(bytes);
    }
}

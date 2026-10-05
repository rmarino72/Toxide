namespace Toxide.Network;

/// <summary>A datagram as received from the socket, waiting to be dispatched.</summary>
public readonly record struct ReceivedPacket(IpPort Source, byte[] Data);
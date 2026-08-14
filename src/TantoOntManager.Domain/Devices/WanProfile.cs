namespace TantoOntManager.Domain.Devices;

public sealed record WanProfile(
    string Name,
    string? Mode,
    string? ServiceList,
    string? LinkType,
    string? IpType,
    string? AddressFamily,
    bool? NatEnabled,
    int? VlanId,
    int? Priority8021p,
    string? ConnectionState,
    string? DisconnectReason,
    string? Ipv4Address,
    string? MacAddress = null,
    string? PppoeUsername = null,
    bool? VlanEnabled = null,
    string? Mtu = null,
    string? Dns = null,
    string? Gateway = null,
    string? Duration = null)
{
    public string Summary
        => string.Join(" · ", new[]
        {
            Name,
            Mode,
            ServiceList,
            VlanId is null ? null : $"VLAN {VlanId}",
            ConnectionState
        }.Where(part => !string.IsNullOrWhiteSpace(part)));
}

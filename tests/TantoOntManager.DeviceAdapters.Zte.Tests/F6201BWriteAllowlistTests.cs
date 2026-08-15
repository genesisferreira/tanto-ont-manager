using FluentAssertions;
using TantoOntManager.DeviceAdapters.Zte.Auth;
using TantoOntManager.Domain.Devices;

namespace TantoOntManager.DeviceAdapters.Zte.Tests;

public sealed class F6201BWriteAllowlistTests
{
    [Fact]
    public void Write_allowlist_remains_empty_and_rejects_every_method()
    {
        F6201BV9310P8N1WriteAllowlist.IsEmpty.Should().BeTrue();
        F6201BV9310P8N1WriteAllowlist.Endpoints.Should().BeEmpty();
        F6201BV9310P8N1WriteAllowlist.Allows("POST", "/?_tag=wanSave").Should().BeFalse();
        F6201BV9310P8N1WriteAllowlist.Allows("PUT", "/").Should().BeFalse();
        F6201BFirmwareCompatibility.AllowsWrite(FirmwareCompatibility.ConfirmedCompatible).Should().BeFalse();
    }
}

public sealed class Phase2AHomologatedReadRegressionTests
{
    [Fact]
    public void Phase2A_regression_device_pon_wan_routes_remain_homologated()
    {
        var device = F6201BV9310P8N1HomologatedReadContract.BuildPath(
            F6201BV9310P8N1HomologatedReadContract.Device, "1");
        var pon = F6201BV9310P8N1HomologatedReadContract.BuildPath(
            F6201BV9310P8N1HomologatedReadContract.Pon, "1");
        var status = F6201BV9310P8N1HomologatedReadContract.BuildPath(
            F6201BV9310P8N1HomologatedReadContract.WanStatus, "1");
        var config = F6201BV9310P8N1HomologatedReadContract.BuildPath(
            F6201BV9310P8N1HomologatedReadContract.WanConfig, "1");

        F6201BV9310P8N1HomologatedReadContract.BuildPath(
                F6201BV9310P8N1HomologatedReadContract.DeviceTemplate, "1")
            .Should().Contain("_type=menuView").And.Contain("_tag=statusMgr");
        device.Should().Contain("_type=menuData").And.Contain("_tag=devmgr_statusmgr_lua.lua");
        F6201BV9310P8N1HomologatedReadContract.BuildPath(
                F6201BV9310P8N1HomologatedReadContract.PonTemplate, "1")
            .Should().Contain("_tag=ponopticalinfo");
        pon.Should().Contain("_tag=optical_info_lua.lua");
        F6201BV9310P8N1HomologatedReadContract.BuildPath(
                F6201BV9310P8N1HomologatedReadContract.WanStatusTemplate, "1")
            .Should().Contain("_tag=ethWanStatus");
        status.Should().Contain("_tag=wan_internetstatus_lua.lua")
            .And.Contain("TypeUplink=2")
            .And.Contain("pageType=1");
        F6201BV9310P8N1HomologatedReadContract.BuildPath(
                F6201BV9310P8N1HomologatedReadContract.WanConfigTemplate, "1")
            .Should().Contain("_tag=ethWanConfig");
        config.Should().Contain("_tag=wan_internet_lua.lua")
            .And.Contain("TypeUplink=2")
            .And.Contain("pageType=0");
    }

    [Fact]
    public void Phase2A1_regression_device_pon_wan_routes_remain_homologated()
        => Phase2A_regression_device_pon_wan_routes_remain_homologated();
}

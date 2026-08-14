using FluentAssertions;
using TantoOntManager.DeviceAdapters.Zte.Auth;
using TantoOntManager.Domain.Discovery;

namespace TantoOntManager.DeviceAdapters.Zte.Tests;

public sealed class F6201BStaticRouteResolverTests
{
    private static string Fixture(string name)
        => File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", name));

    [Fact]
    public void Resolves_literal_assignment_and_safe_concatenation()
    {
        var source = """
            var pageurl = "pon_status";
            openLink("/?_type=menuView&_tag=" + pageurl);
            """;
        var resolved = F6201BStaticRouteResolver.Resolve(source);
        resolved.Routes.Should().Contain(route =>
            route.Type == "menuView"
            && route.Tag == "pon_status"
            && route.Variable == "pageurl"
            && route.LiteralValue == "pon_status"
            && !route.Unresolved);
    }

    [Fact]
    public void Resolves_literal_alias()
    {
        var source = """
            var pageurl = "pon_status";
            var alias = pageurl;
            var data = "/?_type=menuData&_tag=" + alias;
            """;
        var resolved = F6201BStaticRouteResolver.Resolve(source);
        resolved.Routes.Should().Contain(route => route.Type == "menuData" && route.Tag == "pon_status" && route.Variable == "alias");
    }

    [Fact]
    public void Resolves_concatenation_of_literals()
    {
        var source = """
            var pageurl = "pon_" + "status";
            var url = "/?_type=menuView&_tag=" + pageurl;
            """;
        var resolved = F6201BStaticRouteResolver.Resolve(source);
        resolved.Routes.Should().Contain(route => route.Tag == "pon_status" && route.Type == "menuView");
    }

    [Fact]
    public void Resolves_menu_object_with_unquoted_keys()
    {
        var nodes = F6201BMenuTreeExtractor.Extract(Fixture("zte-f6201b-v9310p8n1-js-object-menu.html"));
        nodes.Should().Contain(node => node.Id == "devStatus" && node.Kind == "page" && node.Path.Contains("Management & Diagnosis"));
        nodes.Should().Contain(node => node.Id == "ponInfo" && node.Path == "Internet → PON Information");
        nodes.Should().Contain(node => node.Id == "internet" && node.Kind == "folder");
        nodes.Should().NotContain(node => node.Id == "1");
    }

    [Fact]
    public void Resolves_pageurl_MenuPage_and_Menu3Location()
    {
        var items = F6201BSafeReadDiscovery.Discover(Fixture("zte-f6201b-v9310p8n1-js-object-menu.html"));
        items.Should().Contain(item =>
            item.Tag == "devStatus"
            && item.ExtraParameters.ContainsKey("Menu3Location")
            && item.ExtraParameters["Menu3Location"] == "0"
            && item.RouteKind == AuthenticatedRouteKind.MenuLeaf);
        items.Should().Contain(item => item.Tag == "pon_status" && item.Classification == SafeReadClassification.SafeRead);
        items.Should().Contain(item => item.Tag == "internet" && item.RouteKind == AuthenticatedRouteKind.MenuFolder && item.Classification == SafeReadClassification.UnknownNotAccessed);
    }

    [Fact]
    public void Allows_proven_extra_parameter_and_blocks_dynamic_extra()
    {
        var proven = F6201BSafeReadDiscovery.Discover("""var extra = "/?_type=hiddenData&_tag=accessdev_data&DeveiceType=PC";""");
        proven.Should().Contain(item =>
            item.Tag == "accessdev_data"
            && item.Classification == SafeReadClassification.SafeRead
            && item.ExtraParameters["DeveiceType"] == "PC"
            && item.RouteKind == AuthenticatedRouteKind.DataEndpoint);

        var dynamic = F6201BStaticRouteResolver.Resolve("""var extra = "/?_type=hiddenData&_tag=accessdev_data&DeveiceType=" + userType;""");
        dynamic.Routes.Should().Contain(route => route.Unresolved && route.Kind == AuthenticatedRouteKind.UnresolvedDynamicRoute);
        dynamic.UnresolvedReasons.Should().NotBeEmpty();
    }

    [Fact]
    public void Blocks_user_input_and_dynamic_function()
    {
        var input = F6201BStaticRouteResolver.Resolve("""var pageurl = $("#Frm_Username").val(); openLink("/?_type=menuView&_tag=" + pageurl);""");
        input.Routes.Should().Contain(route => route.Unresolved);
        input.Routes.Should().NotContain(route => route.Tag == "Frm_Username" && !route.Unresolved);

        var fn = F6201BStaticRouteResolver.Resolve("""pageurl = calculatePage(userInput); var url = "/?_type=menuView&_tag=" + pageurl;""");
        fn.Routes.Should().Contain(route => route.Unresolved && route.Variable == "pageurl");
        fn.Routes.Should().NotContain(route => !route.Unresolved && route.Type == "menuView" && route.EvidenceSource.Contains("concat"));
    }

    [Fact]
    public void Resolver_source_never_uses_eval_or_js_engine()
    {
        F6201BStaticRouteResolver.UsesEvalOrJsEngine.Should().BeFalse();
        var csproj = Path.GetFullPath(Path.Combine(
            AppContext.BaseDirectory, "..", "..", "..", "..", "..",
            "src", "TantoOntManager.DeviceAdapters.Zte", "TantoOntManager.DeviceAdapters.Zte.csproj"));
        File.Exists(csproj).Should().BeTrue();
        var project = File.ReadAllText(csproj);
        project.Should().NotContain("Jint");
        project.Should().NotContain("ClearScript");
        project.Should().NotContain("JavaScriptEngine");
        project.Should().NotContain("Jurassic");
    }

    [Fact]
    public void Folder_is_not_safe_read_and_homepage_is_shell()
    {
        var items = F6201BSafeReadDiscovery.Discover(Fixture("zte-f6201b-v9310p8n1-homepage-shell.html"));
        items.Should().Contain(item => item.Tag == "firewall_homepage_lua" && item.RouteKind == AuthenticatedRouteKind.HomepageShell && item.Classification == SafeReadClassification.SafeRead);
        items.Should().NotContain(item => item.Tag == "home" && item.Classification == SafeReadClassification.SafeRead && item.RouteKind == AuthenticatedRouteKind.MenuFolder);
        items.Should().Contain(item => item.Tag == "home" && (item.RouteKind == AuthenticatedRouteKind.MenuLeaf || item.Classification == SafeReadClassification.SafeRead));
    }
}

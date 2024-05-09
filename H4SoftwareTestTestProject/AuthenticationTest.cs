using Bunit;
using Bunit.TestDoubles;
using H4SoftwareTest.Components.Pages;

namespace H4SoftwareTestTestProject;

public class AuthenticationTest
{
    [Fact]
    public void AuthenticationView()
    {
        //Arange
        var ctx = new TestContext();
        var authContext = ctx.AddTestAuthorization();
        authContext.SetAuthorized("");

        //Act
        var cut = ctx.RenderComponent<Home>();

        //Assert
        cut.MarkupMatches("<h1>Hello, world!</h1>\r\n<br />\r\n<div>Hello again</div>");
    }

    [Fact]
    public void AuthenticationCode()
    {
        //Arange
        var ctx = new TestContext();
        var authContext = ctx.AddTestAuthorization();
        authContext.SetAuthorized("");

        //Act
        var cut = ctx.RenderComponent<Home>();
        var homeObj = cut.Instance;

        //Assert
        Assert.False(homeObj.());
    }
}
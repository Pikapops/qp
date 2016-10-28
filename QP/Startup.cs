using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(QP.Startup))]
namespace QP
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}

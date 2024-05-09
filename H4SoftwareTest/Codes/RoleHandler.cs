using H4SoftwareTest.Data;
using Microsoft.AspNetCore.Identity;

namespace H4SoftwareTest.Codes;

public class RoleHandler
{
    public async Task<bool> CreateUserRolesAsync(string user, string role, IServiceProvider serviceProvider)
    {
        bool isCreated = false;
        try
        {
            var roleManager = serviceProvider.GetRequiredService<RoleManager<IdentityRole>>();
            var userManager = serviceProvider.GetRequiredService<UserManager<ApplicationUser>>();

            var userRoleCheck = await roleManager.RoleExistsAsync(role);
            if (!userRoleCheck)
            {
                var roleObj = new IdentityRole(role);
                await roleManager.CreateAsync(roleObj);
            }

            ApplicationUser identityUser = await userManager.FindByEmailAsync(user);
            await userManager.AddToRoleAsync(identityUser, role);

            isCreated = true;
        }
        catch(Exception)
        {
            isCreated = false;
        }
        return isCreated;
    }
}

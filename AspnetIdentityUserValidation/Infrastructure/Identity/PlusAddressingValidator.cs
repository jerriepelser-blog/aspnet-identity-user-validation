using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;

namespace AspnetIdentityUserValidation.Infrastructure.Identity;

public partial class PlusAddressingValidator : IUserValidator<IdentityUser>
{
    public Task<IdentityResult> ValidateAsync(UserManager<IdentityUser> manager, IdentityUser user)
    {
        if (string.IsNullOrEmpty(user.Email))
        {
            return Task.FromResult(IdentityResult.Success);
        }

        if (PlusAddressingRegex().Match(user.Email) is { Success: true } match)
        {
            return Task.FromResult(
                IdentityResult.Failed(
                    new IdentityError
                    {
                        Code = "USER_PLUS_ADDRESSING_DISALLOWED",
                        Description =
                            $"An email with a sub-address ({match.Groups["subaddress"].Value}) is not allowed. Use only the primary email address - i.e. {match.Groups["username"].Value}@{match.Groups["domain"].Value}",
                    }
                )
            );
        }

        return Task.FromResult(IdentityResult.Success);
    }

    [GeneratedRegex(@"^(?<username>.+)(?<subaddress>\+.*)@(?<domain>.+)$")]
    private static partial Regex PlusAddressingRegex();
}

using System;
using System.Globalization;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System.Data.Entity.SqlServer.Utilities;

namespace AlwaysEncryptedIdentity
{
    public class UserManagerExtension<TUser, TKey> : UserManager<TUser, string> where TUser : IdentityUser, IUser<string>
    {
        private bool _disposed;
        private readonly IdentityDbContext<TUser> dbContext;
        private new IUserStore<TUser, string> Store { get; set; }
       

        public UserManagerExtension(IUserStore<TUser, string> store) : base(store)
        {
            dbContext = new IdentityDbContext<TUser>("DefaultConnection");
            Store = new UserStoreExtension<TUser>(dbContext);
        }

        public override async Task<IdentityResult> CreateAsync(TUser user, string password)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            if (password == null)
            {
                throw new ArgumentNullException("password");
            }
            var result = await UserValidator.ValidateAsync(user).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            result = await PasswordValidator.ValidateAsync(password).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            result = await UpdatePassword(GetPasswordStore(), user, password).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            await Store.CreateAsync(user).WithCurrentCulture();
            return IdentityResult.Success;
        }

        public override async Task<IdentityResult> ConfirmEmailAsync(string userId, string token)
        {
            ThrowIfDisposed();
            var store = GetEmailStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "UserIdNotFound", userId));
            }
            if (!await VerifyUserTokenAsync(userId, "Confirmation", token).WithCurrentCulture())
            {
                return IdentityResult.Failed("InvalidToken");
            }
            await store.SetEmailConfirmedAsync(user, true).WithCurrentCulture();
            return await UpdateAsync(user).WithCurrentCulture();
        }
        
        private IUserPasswordStore<TUser, string> GetPasswordStore()
        {
            var cast = Store as IUserPasswordStore<TUser, string>;
            if (cast == null)
            {
                throw new NotSupportedException("StoreNotIUserPasswordStore");
            }
            return cast;
        }

        private IUserEmailStore<TUser, string> GetEmailStore()
        {
            var cast = Store as IUserEmailStore<TUser, string>;
            if (cast == null)
            {
                throw new NotSupportedException("StoreNotIUserEmailStore");
            }
            return cast;
        }

        private IUserSecurityStampStore<TUser, string> GetSecurityStore()
        {
            var cast = Store as IUserSecurityStampStore<TUser, string>;
            if (cast == null)
            {
                throw new NotSupportedException("StoreNotIUserSecurityStampStore");
            }
            return cast;
        }

        private void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);
            _disposed = true;
        }        
    }
}

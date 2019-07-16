using System;
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
       

        public UserManagerExtension(IUserStore<TUser, string> store, string connectionStringName = "DefaultConnection") : base(store)
        {
            dbContext = new IdentityDbContext<TUser>(connectionStringName);
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
        
        private IUserPasswordStore<TUser, string> GetPasswordStore()
        {
            if (Store is IUserPasswordStore<TUser, string> cast)
            {
                return cast;
            }
            throw new NotSupportedException("StoreNotIUserPasswordStore");
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

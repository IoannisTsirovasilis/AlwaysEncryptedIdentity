using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Data.Entity;
using System.Data.Entity.SqlServer.Utilities;
using System.Threading.Tasks;

namespace AlwaysEncryptedIdentity
{
    public class UserStoreExtension<TUser> : UserStore<TUser> where TUser : IdentityUser
    {
        private bool _disposed;
        private readonly DbSet _userStore;
        private new readonly IdentityDbContext<TUser> Context;

        public UserStoreExtension(IdentityDbContext<TUser> context)
            : base(context)
        {
            Context = context;
            _userStore = Context.Set<TUser>();
        }

        public override async Task CreateAsync(TUser user)
        {
            ThrowIfDisposed();
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }
            _userStore.Add(user);
            await SaveChanges().WithCurrentCulture();
        }

        public override async Task<TUser> FindByNameAsync(string userName)
        {
            ThrowIfDisposed();
            userName = userName.ToLower();
            return await GetUserAggregateAsync(u => u.UserName == userName);
        }

        public override async Task<TUser> FindByEmailAsync(string email)
        {
            ThrowIfDisposed();
            email = email.ToLower();
            return await GetUserAggregateAsync(u => u.Email == email);
        }

        private async Task SaveChanges()
        {
            if (AutoSaveChanges)
            {
                await Context.SaveChangesAsync().WithCurrentCulture();
            }
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

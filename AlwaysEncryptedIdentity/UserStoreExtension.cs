using Microsoft.AspNet.Identity.EntityFramework;
using System;
using System.Data.Entity;
using System.Threading.Tasks;

namespace AlwaysEncryptedIdentity
{
    public class UserStoreExtension<TUser> : UserStore<TUser> where TUser : IdentityUser
    {
        private bool _disposed;

        public UserStoreExtension(DbContext context)
            : base(context)
        {
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

        public override async Task<TUser> FindByIdAsync(string userId)
        {
            ThrowIfDisposed();
            return await GetUserAggregateAsync(u => u.Id == userId);
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

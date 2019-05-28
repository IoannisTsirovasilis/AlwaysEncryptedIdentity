using System;
using System.Globalization;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using System.Data.SqlClient;
using System.Data.Entity;
using System.Web.Helpers;
using System.Data.Entity.SqlServer.Utilities;

namespace AlwaysEncryptedIdentity
{
    public class UserManagerExtension<TUser, TKey> : UserManager<TUser, string> where TUser : IdentityUser, IUser<string>
    {
        private dynamic db;
        private bool _disposed;
        private new IUserStore<TUser, string> Store { get; set; }

        public UserManagerExtension(IUserStore<TUser, string> store, dynamic db) : base(store)
        {
            Store = store;
            this.db = db;
        }

        public virtual async Task<IdentityResult> CreateAsync(TUser user, string password)
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
            do
            {
                user.Id = Guid.NewGuid().ToString();
            } while (await db.AspNetUsers.FindAsync(user.Id).ConfigureAwait(false) != null);
            var sql = GetInsertUserQuery();
            await db.Database.ExecuteSqlCommandAsync(
                sql,
                new SqlParameter("@Id", user.Id),
                new SqlParameter("@Email", user.Email.ToLower()),
                new SqlParameter("@EmailConfirmed", user.EmailConfirmed),
                new SqlParameter("@PasswordHash", Crypto.HashPassword(password)),
                new SqlParameter("@PhoneNumber", user.PhoneNumber ?? (object)DBNull.Value),
                new SqlParameter("@PhoneNumberConfirmed", user.PhoneNumberConfirmed),
                new SqlParameter("@TwoFactorEnabled", user.TwoFactorEnabled),
                new SqlParameter("@LockoutEndDateUtc", user.LockoutEndDateUtc ?? (object)DBNull.Value),
                new SqlParameter("@LockoutEnabled", user.LockoutEnabled),
                new SqlParameter("@AccessFailedCount", user.AccessFailedCount),
                new SqlParameter("@UserName", user.UserName.ToLower())
            ).ConfigureAwait(false);
            await db.SaveChangesAsync().ConfigureAwait(false);
            await UpdateSecurityStampAsync(user.Id).WithCurrentCulture();
            return IdentityResult.Success;
        }

        public override async Task<IdentityResult> ConfirmEmailAsync(string userId, string token)
        {
            ThrowIfDisposed();
            var user = await db.AspNetUsers.FindAsync(userId).ConfigureAwait(false);

            if (user == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "User Id Not Found",
                    userId));
            }
            if (!await VerifyUserTokenAsync(userId, "Confirmation", token).WithCurrentCulture())
            {
                return IdentityResult.Failed("Failed");
            }
            user.EmailConfirmed = true;
            db.Entry(user).State = EntityState.Modified;
            await db.SaveChangesAsync().ConfigureAwait(false);
            return IdentityResult.Success;
        }

        public override async Task<IdentityResult> UpdateSecurityStampAsync(string userId)
        {
            ThrowIfDisposed();
            var securityStore = GetSecurityStore();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "User Id Not Found",
                    userId));
            }
            var securityStamp = Guid.NewGuid().ToString();
            await securityStore.SetSecurityStampAsync(user, securityStamp).WithCurrentCulture();
            var aspNetUser = await db.AspNetUsers.FindAsync(userId).ConfigureAwait(false);
            aspNetUser.SecurityStamp = securityStamp;
            db.Entry(aspNetUser).State = EntityState.Modified;
            await db.SaveChangesAsync().ConfigureAwait(false);
            return IdentityResult.Success;
        }

        public override async Task<IdentityResult> ResetPasswordAsync(string userId, string token, string newPassword)
        {
            ThrowIfDisposed();
            var user = await FindByIdAsync(userId).WithCurrentCulture();
            if (user == null)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "User Id Not Found",
                    userId));
            }
            // Make sure the token is valid and the stamp matches
            if (!await VerifyUserTokenAsync(user.Id, "ResetPassword", token).WithCurrentCulture())
            {
                return IdentityResult.Failed("Invalid Token");
            }
            var passwordStore = GetPasswordStore();
            var result = await UpdatePassword(passwordStore, user, newPassword).WithCurrentCulture();

            return result;
        }

        protected override async Task<IdentityResult> UpdatePassword(IUserPasswordStore<TUser, string> passwordStore,
            TUser user, string newPassword)
        {
            var result = await PasswordValidator.ValidateAsync(newPassword).WithCurrentCulture();
            if (!result.Succeeded)
            {
                return result;
            }
            var aspNetUser = await db.AspNetUsers.FindAsync(user.Id).ConfigureAwait(false);
            aspNetUser.PasswordHash = Crypto.HashPassword(newPassword);
            db.Entry(aspNetUser).State = EntityState.Modified;
            await db.SaveChangesAsync().ConfigureAwait(false);
            await UpdateSecurityStampAsync(user.Id).WithCurrentCulture();
            return IdentityResult.Success;
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

        private string GetInsertUserQuery()
        {
            return @"INSERT INTO [dbo].[AspNetUsers] (Id, Email, EmailConfirmed, PasswordHash, PhoneNumber, PhoneNumberConfirmed,
                     TwoFactorEnabled, LockoutEndDateUtc, LockoutEnabled, AccessFailedCount, UserName)
                     VALUES (@Id, @Email, @EmailConfirmed, @PasswordHash, @PhoneNumber, 
                     @PhoneNumberConfirmed, @TwoFactorEnabled, @LockoutEndDateUtc, @LockoutEnabled,
                     @AccessFailedCount, @UserName)";
        }
    }
}

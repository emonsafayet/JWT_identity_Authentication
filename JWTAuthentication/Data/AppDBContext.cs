using JWTAuthentication.Data.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JWTAuthentication.Data
{
    public class AppDBContext :IdentityDbContext<AppUser,IdentityRole,string>
    {
        public AppDBContext(DbContextOptions options):base(options)
        {

        }
    }
}

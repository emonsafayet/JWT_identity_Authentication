﻿using JWTAuthentication.BindingModel;
using JWTAuthentication.Data.Entities;
using JWTAuthentication.DTO;
using JWTAuthentication.Enums;
using JWTAuthentication.Models;
using JWTAuthentication.Models.BindingModel;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JWTAuthentication.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : ControllerBase
    {

        private readonly ILogger<UserController> _logger;
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly RoleManager<IdentityRole> _rolewManager;

        private readonly JWTConfig _jWTConfig;


        public UserController(ILogger<UserController> logger, IOptions<JWTConfig> jWTConfig,
            UserManager<AppUser> userManager, SignInManager<AppUser> signInManager, RoleManager<IdentityRole> rolewManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
            _jWTConfig = jWTConfig.Value;
            _rolewManager = rolewManager;
        }

        [HttpPost("RegisterUser")]
        public async Task<object> RegisterUser([FromBody] AddUpdateRegisterUserBindingModel model)
        {
            try
            {
                if(model.Roles==null)
                    return await Task.FromResult(new ResponseModel(ResponseCode.Error, "Roles are missing", null));

                foreach (var role in model.Roles)
                {
                    if (!await _rolewManager.RoleExistsAsync(role))
                    {
                        return await Task.FromResult(new ResponseModel(ResponseCode.Error, "Role does not exist", null));
                    }
                }
                var user = new AppUser()
                {
                    FullName = model.FullName,
                    Email = model.Email,
                    DateCreated = DateTime.UtcNow,
                    DateModified = DateTime.UtcNow,
                    UserName = model.Email
                };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    var tempUser = await _userManager.FindByEmailAsync(model.Email);
                    foreach (var role in model.Roles)
                    {
                        await _userManager.AddToRoleAsync(tempUser, role);
                    }
                    return await Task.FromResult(new ResponseModel(ResponseCode.OK, "User Has Been Registered!", null));
                }

                return await Task.FromResult(new ResponseModel(ResponseCode.Error, "", result.Errors.Select(x => x.Description).ToArray()));
            }
            catch (Exception ex)
            {

                return await Task.FromResult(new ResponseModel(ResponseCode.Error, ex.Message, null));
            }

        }

        [Authorize(Policy = "AdminPolicy")]
        [HttpGet("GetAllUser")]
        public async Task<object> GetAllUser()
        {
            try
            {
                List<UserDTO> allUserDTO = new List<UserDTO>();
                var users = _userManager.Users.ToList();
                foreach (var user in users)
                {
                    var roles = (await _userManager.GetRolesAsync(user)).ToList();

                    allUserDTO.Add(new UserDTO(user.FullName, user.Email, user.UserName, user.DateCreated, roles));
                }
                return await Task.FromResult(new ResponseModel(ResponseCode.OK, null, allUserDTO));
            }
            catch (Exception ex)
            {

                return await Task.FromResult(new ResponseModel(ResponseCode.Error, ex.Message, null));
            }
        }

        [Authorize(Roles = "User,Admin")]
        [HttpGet("GetUserList")]
        public async Task<object> GetUserList()
        {
            try
            {
                List<UserDTO> allUserDTO = new List<UserDTO>();
                var users = _userManager.Users.ToList();
                foreach (var user in users)
                {
                    var role = (await _userManager.GetRolesAsync(user)).ToList();
                    if (role.Any(x => x == "User"))
                    {
                        allUserDTO.Add(new UserDTO(user.FullName, user.Email, user.UserName, user.DateCreated, role));
                    }
                }
                return await Task.FromResult(new ResponseModel(ResponseCode.OK, null, allUserDTO));
            }
            catch (Exception ex)
            {

                return await Task.FromResult(new ResponseModel(ResponseCode.Error, ex.Message, null));
            }
        }

        [HttpPost("Login")]
        public async Task<object> Login([FromBody] LoginBindingModel model)
        {
            try
            {
                if (ModelState.IsValid)
                {
                    var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, false, false); ;
                    if (result.Succeeded)
                    {
                        var appUser = await _userManager.FindByEmailAsync(model.Email);
                        var roles = (await _userManager.GetRolesAsync(appUser)).ToList();
                        var user = new UserDTO(appUser.FullName, appUser.Email, appUser.UserName, appUser.DateCreated, roles);
                        user.Token = GenerateToken(appUser, roles);

                        return await Task.FromResult(new ResponseModel(ResponseCode.OK, "", user));
                    }
                }
                return await Task.FromResult(new ResponseModel(ResponseCode.Error, "Invalid Email or Passowrd", null));

            }
            catch (Exception ex)
            {
                return await Task.FromResult(new ResponseModel(ResponseCode.Error, ex.Message, null));
            }
        }

        [Authorize(Roles = "Admin")]
        [HttpPost("AddRole")]
        public async Task<object> AddRole([FromBody] AddRoleBindingModel model)
        {
            try
            {
                if (model == null && model.Role == "")
                {
                    return await Task.FromResult(new ResponseModel(ResponseCode.Error, "Parameters are missing", null));
                }
                if (await _rolewManager.RoleExistsAsync(model.Role))
                {
                    return await Task.FromResult(new ResponseModel(ResponseCode.OK, "Role already exist", null));
                }
                var role = new IdentityRole();
                role.Name = model.Role;
                var result = await _rolewManager.CreateAsync(role);
                if (result.Succeeded)
                {
                    return await Task.FromResult(new ResponseModel(ResponseCode.OK, "Role added Successfully", null));
                }
                return await Task.FromResult(new ResponseModel(ResponseCode.Error, "something want please try again later", null));
            }
            catch (Exception ex)
            {

                return await Task.FromResult(new ResponseModel(ResponseCode.Error, ex.Message, null));
            }
        }

        [HttpGet("GetRoles")]
        public async Task<object> GetRoles()
        {
            try
            {
                var roles = _rolewManager.Roles.Select(x => x.Name).ToList();
                return await Task.FromResult(new ResponseModel(ResponseCode.OK, null, roles));
            }
            catch (Exception ex)
            {

                return await Task.FromResult(new ResponseModel(ResponseCode.Error, ex.Message, null));
            }
        }

        private string GenerateToken(AppUser user, List<string> roles)
        {
            var claims = new List<System.Security.Claims.Claim>()
            {
                  new System.Security.Claims.Claim(JwtRegisteredClaimNames.NameId, user.Id),
                  new System.Security.Claims.Claim(JwtRegisteredClaimNames.Email, user.Email),
                  new System.Security.Claims.Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),

            };
            foreach (var role in roles)
            {
                claims.Add(new System.Security.Claims.Claim(ClaimTypes.Role, role));
            }
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jWTConfig.key);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new System.Security.Claims.ClaimsIdentity(claims),

                Expires = DateTime.UtcNow.AddHours(12),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Audience = _jWTConfig.Audience,
                Issuer = _jWTConfig.Issuer,
            };
            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            return jwtTokenHandler.WriteToken(token);
        }
    }
}

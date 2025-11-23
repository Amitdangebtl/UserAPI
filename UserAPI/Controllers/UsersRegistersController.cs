using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Data.SqlClient;
using System.Security.Cryptography;
using System.Text;
using System.Globalization;
using UserAPI.Models;
using System.Net;
using System.Net.Mail;

namespace UserAPI.Controllers
{
    [ApiController]
    [Route("api/usersregisters")]
    [Produces("application/json")]
    public class UsersRegistersController : ControllerBase
    {
        private readonly MyDbDatabaseContext _context;
        private readonly IConfiguration _config;

        public UsersRegistersController(MyDbDatabaseContext context, IConfiguration config)
        {
            _context = context;
            _config = config;
        }

        private static bool TryParseDob(string? input, out DateOnly? dob)
        {
            dob = null;
            if (string.IsNullOrWhiteSpace(input)) return true;

            string[] formats = { "yyyy-MM-dd", "yyyy/MM/dd", "dd-MM-yyyy", "dd/MM/yyyy" };

            if (DateOnly.TryParseExact(input.Trim(), formats, CultureInfo.InvariantCulture,
                                       DateTimeStyles.None, out var d1))
            {
                dob = d1;
                return true;
            }

            if (DateTime.TryParse(input.Trim(), CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
            {
                dob = DateOnly.FromDateTime(dt);
                return true;
            }

            return false;
        }

        private static DateTime? ToDateTimeOrNull(DateOnly? d) =>
            d.HasValue ? d.Value.ToDateTime(TimeOnly.MinValue) : (DateTime?)null;

        private static string ComputeSha256(string input)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(input ?? ""));
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }

        #region Register / Login
        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterRequest model)
        {
            if (model == null) return BadRequest("Request body is required.");

            if (string.IsNullOrWhiteSpace(model.Email))
                return BadRequest("Email is required.");
            if (string.IsNullOrWhiteSpace(model.Password))
                return BadRequest("Password is required.");

            var exists = await _context.UsersRegisters.AnyAsync(u => u.Email == model.Email);
            if (exists) return Conflict("Email already registered.");

            DateOnly? dob = null;
            if (!TryParseDob(model.Dob, out dob))
                return BadRequest("Invalid DOB. Use format yyyy-MM-dd or dd/MM/yyyy.");

            string passwordHash = ComputeSha256(model.Password ?? "");

            var entity = new UsersRegister
            {
                FirstName = (model.FirstName ?? "").Trim(),
                LastName = (model.LastName ?? "").Trim(),
                Email = (model.Email ?? "").Trim(),
                Gender = model.Gender,
                Dob = dob,
                Country = model.Country,
                Address = model.Address,
                ProfileImagePath = model.ProfileImagePath,
                PasswordHash = passwordHash,
                IsTermsAccepted = model.IsTermsAccepted,
                State = model.State,
                City = model.City,
                CreatedAt = DateTime.UtcNow
            };

            _context.UsersRegisters.Add(entity);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetUsersRegister),
                new { id = entity.UserId },
                new
                {
                    entity.UserId,
                    entity.FirstName,
                    entity.LastName,
                    entity.Email,
                    entity.Gender,
                    DOB = ToDateTimeOrNull(entity.Dob),
                    entity.Country,
                    entity.Address,
                    entity.ProfileImagePath,
                    entity.State,
                    entity.City
                });
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest model)
        {
            if (model == null || string.IsNullOrWhiteSpace(model.Email) || string.IsNullOrWhiteSpace(model.Password))
                return BadRequest("Email and Password are required.");

            string hash = ComputeSha256(model.Password);
            string cs = _config.GetConnectionString("TestAPIConnection");
            if (string.IsNullOrWhiteSpace(cs))
                return StatusCode(500, "Connection string 'TestAPIConnection' not found.");

            try
            {
                using var con = new SqlConnection(cs);
                con.Open();

                using var cmd = new SqlCommand(@"
SELECT TOP 1 
    u.[UserID], u.[FirstName], u.[LastName], u.[Email], u.[Gender], u.[DOB],
    u.[Country], u.[Address], u.[ProfileImagePath], u.[State], u.[City],
    u.[RoleId], r.[RoleName]
FROM [dbo].[Users_Register] u
LEFT JOIN [dbo].[Roles] r ON r.RoleId = u.RoleId
WHERE u.[Email] = @Email AND u.[PasswordHash] = @Hash;", con);

                cmd.Parameters.AddWithValue("@Email", model.Email);
                cmd.Parameters.AddWithValue("@Hash", hash);

                using var rdr = cmd.ExecuteReader();
                if (!rdr.Read())
                    return Unauthorized("Invalid email or password.");

                int userId = rdr.GetInt32(rdr.GetOrdinal("UserID"));

                string? first = rdr["FirstName"] as string;
                string? last = rdr["LastName"] as string;
                string? email = rdr["Email"] as string;
                string? gender = rdr["Gender"] as string;

                DateTime? dob = null;
                int dobOrdinal = rdr.GetOrdinal("DOB");
                if (!rdr.IsDBNull(dobOrdinal))
                {
                    dob = rdr.GetFieldValue<DateTime>(dobOrdinal);
                }

                string? country = rdr["Country"] as string;
                string? address = rdr["Address"] as string;
                string? imgPath = rdr["ProfileImagePath"] as string;
                string? state = rdr["State"] as string;
                string? city = rdr["City"] as string;
                int? roleId = rdr.IsDBNull(rdr.GetOrdinal("RoleId")) ? (int?)null : rdr.GetInt32(rdr.GetOrdinal("RoleId"));
                string? roleName = rdr["RoleName"] as string ?? "User";

                return Ok(new
                {
                    UserID = userId,
                    FirstName = first,
                    LastName = last,
                    Email = email,
                    Gender = gender,
                    DOB = dob,
                    Country = country,
                    Address = address,
                    ProfileImagePath = imgPath,
                    State = state,
                    City = city,
                    RoleId = roleId,
                    RoleName = roleName
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Login error: " + ex.Message);
            }
        }
        #endregion

        #region Forgot Password Endpoints

        [HttpPost("send-reset-link")]
        public async Task<IActionResult> SendResetLink([FromBody] SendResetDto dto)
        {
            if (dto == null || string.IsNullOrWhiteSpace(dto.Email))
                return BadRequest("Email is required.");

            try
            {
                var user = await _context.UsersRegisters.FirstOrDefaultAsync(u => u.Email == dto.Email);
                if (user == null)
                {
                    return Ok(new { message = "If the email exists, a reset link has been sent." });
                }

                user.ResetToken = Guid.NewGuid().ToString("N");
                user.ResetTokenExpiry = DateTime.UtcNow.AddHours(2);

                await _context.SaveChangesAsync();

                string front = _config["AppSettings:FrontendBaseUrl"]?.TrimEnd('/') ?? "https://localhost:44330";
                string resetLink = $"{front}/Register%20Page/ResetPassword.aspx?token={Uri.EscapeDataString(user.ResetToken)}";

                try
                {
                    var smtpHost = _config["Smtp:Host"];
                    var smtpPort = int.Parse(_config["Smtp:Port"] ?? "587");
                    var smtpUser = _config["Smtp:User"];
                    var smtpPass = _config["Smtp:Pass"];
                    var fromEmail = _config["Smtp:From"] ?? smtpUser;

                    var mail = new MailMessage();
                    mail.To.Add(user.Email);
                    mail.From = new MailAddress(fromEmail);
                    mail.Subject = "Password Reset Request";
                    mail.Body = $"Hello {user.FirstName},\n\nPlease click the link below to reset your password:\n\n{resetLink}\n\nIf you did not request this, please ignore this email.";
                    mail.IsBodyHtml = false;

                    using (var smtp = new SmtpClient(smtpHost, smtpPort))
                    {
                        smtp.EnableSsl = true;
                        smtp.Credentials = new NetworkCredential(smtpUser, smtpPass);
                        smtp.Send(mail);
                    }

                    return Ok(new { message = "If the email exists, a reset link has been sent." });
                }
                catch (Exception ex)
                {
                    return StatusCode(500, "Email sending failed: " + ex.Message);
                }
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Error processing request: " + ex.Message);
            }
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto dto)
        {
            // GitHub Test Commit
            if (dto == null || string.IsNullOrWhiteSpace(dto.Token) || string.IsNullOrWhiteSpace(dto.NewPassword))
                return BadRequest("Token and newPassword are required.");

            try
            {
                var user = await _context.UsersRegisters.FirstOrDefaultAsync(u => u.ResetToken == dto.Token);
                if (user == null)
                    return BadRequest("Invalid or expired token.");

                if (user.ResetTokenExpiry == null || user.ResetTokenExpiry < DateTime.UtcNow)
                    return BadRequest("Token expired.");

                string hashed = ComputeSha256(dto.NewPassword);

                user.PasswordHash = hashed;
                user.ResetToken = null;
                user.ResetTokenExpiry = null;

                await _context.SaveChangesAsync();

                return Ok(new { message = "Password updated successfully." });
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Error updating password: " + ex.Message);
            }
        }

        #endregion

        #region Country / State / City dropdown APIs

        // GET: api/usersregisters/countries
        [HttpGet("countries")]
        public async Task<ActionResult<IEnumerable<string>>> GetCountries()
        {
            try
            {
                var countries = await _context.UsersRegisters
                    .Where(u => !string.IsNullOrWhiteSpace(u.Country))
                    .Select(u => u.Country!)
                    .Distinct()
                    .OrderBy(c => c)
                    .ToListAsync();

                return Ok(countries);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Error loading countries: " + ex.Message);
            }
        }

        // GET: api/usersregisters/states?country=India
        [HttpGet("states")]
        public async Task<ActionResult<IEnumerable<string>>> GetStates([FromQuery] string country)
        {
            if (string.IsNullOrWhiteSpace(country))
                return BadRequest("country is required.");

            try
            {
                var states = await _context.UsersRegisters
                    .Where(u => u.Country == country && !string.IsNullOrWhiteSpace(u.State))
                    .Select(u => u.State!)
                    .Distinct()
                    .OrderBy(s => s)
                    .ToListAsync();

                return Ok(states);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Error loading states: " + ex.Message);
            }
        }

        // GET: api/usersregisters/cities?state=Madhya%20Pradesh
        [HttpGet("cities")]
        public async Task<ActionResult<IEnumerable<string>>> GetCities([FromQuery] string state)
        {
            if (string.IsNullOrWhiteSpace(state))
                return BadRequest("state is required.");

            try
            {
                var cities = await _context.UsersRegisters
                    .Where(u => u.State == state && !string.IsNullOrWhiteSpace(u.City))
                    .Select(u => u.City!)
                    .Distinct()
                    .OrderBy(c => c)
                    .ToListAsync();

                return Ok(cities);
            }
            catch (Exception ex)
            {
                return StatusCode(500, "Error loading cities: " + ex.Message);
            }
        }

        #endregion

        #region Read (null-safe projections with sorting)

        [HttpGet]
        public async Task<ActionResult<IEnumerable<UserDto>>> GetUsersRegisters(
            [FromQuery] string? sortBy = "userid",
            [FromQuery] string? sortDir = "asc")
        {
            try
            {
                bool asc = string.Equals(sortDir, "asc", StringComparison.OrdinalIgnoreCase);

                var q = _context.UsersRegisters.AsNoTracking();

                switch ((sortBy ?? "").Trim().ToLowerInvariant())
                {
                    case "fullname":
                        q = asc
                            ? q.OrderBy(x => x.FirstName).ThenBy(x => x.LastName)
                            : q.OrderByDescending(x => x.FirstName).ThenByDescending(x => x.LastName);
                        break;
                    case "firstname":
                        q = asc ? q.OrderBy(x => x.FirstName) : q.OrderByDescending(x => x.FirstName);
                        break;
                    case "lastname":
                        q = asc ? q.OrderBy(x => x.LastName) : q.OrderByDescending(x => x.LastName);
                        break;
                    case "email":
                        q = asc ? q.OrderBy(x => x.Email) : q.OrderByDescending(x => x.Email);
                        break;
                    case "gender":
                        q = asc ? q.OrderBy(x => x.Gender) : q.OrderByDescending(x => x.Gender);
                        break;
                    case "dob":
                        q = asc ? q.OrderBy(x => x.Dob) : q.OrderByDescending(x => x.Dob);
                        break;
                    case "country":
                        q = asc ? q.OrderBy(x => x.Country) : q.OrderByDescending(x => x.Country);
                        break;
                    case "userid":
                    case "id":
                    default:
                        q = asc ? q.OrderBy(x => x.UserId) : q.OrderByDescending(x => x.UserId);
                        break;
                }

                var list = await q.Select(u => new UserDto
                {
                    UserID = u.UserId,
                    FirstName = u.FirstName ?? string.Empty,
                    LastName = u.LastName ?? string.Empty,
                    Email = u.Email ?? string.Empty,
                    Gender = u.Gender ?? string.Empty,
                    DOB = u.Dob.HasValue ? u.Dob.Value.ToDateTime(TimeOnly.MinValue) : (DateTime?)null,
                    Country = u.Country ?? string.Empty,
                    Address = u.Address ?? string.Empty,
                    ProfileImagePath = u.ProfileImagePath ?? string.Empty,
                    State = u.State ?? string.Empty,
                    City = u.City ?? string.Empty
                }).ToListAsync();

                return Ok(list);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error reading users: {ex.Message}");
            }
        }

        [HttpGet("{id:int}")]
        public async Task<ActionResult<UserDto>> GetUsersRegister(int id)
        {
            try
            {
                var u = await _context.UsersRegisters
                    .AsNoTracking()
                    .Where(x => x.UserId == id)
                    .Select(x => new UserDto
                    {
                        UserID = x.UserId,
                        FirstName = x.FirstName ?? string.Empty,
                        LastName = x.LastName ?? string.Empty,
                        Email = x.Email ?? string.Empty,
                        Gender = x.Gender ?? string.Empty,
                        DOB = x.Dob.HasValue ? x.Dob.Value.ToDateTime(TimeOnly.MinValue) : (DateTime?)null,
                        Country = x.Country ?? string.Empty,
                        Address = x.Address ?? string.Empty,
                        ProfileImagePath = x.ProfileImagePath ?? string.Empty,
                        State = x.State ?? string.Empty,
                        City = x.City ?? string.Empty
                    })
                    .SingleOrDefaultAsync();

                if (u == null) return NotFound();

                return Ok(u);
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Error loading user: {ex.Message}");
            }
        }
        #endregion

        #region Update / Delete
        [HttpPut("{id:int}")]
        public async Task<IActionResult> PutUsersRegister(int id, [FromBody] UpdateUserDto dto)
        {
            if (dto == null) return BadRequest("Request body required.");

            try
            {
                var u = await _context.UsersRegisters.FindAsync(id);
                if (u == null) return NotFound();

                u.FirstName = string.IsNullOrWhiteSpace(dto.FirstName) ? u.FirstName : dto.FirstName.Trim();
                u.LastName = string.IsNullOrWhiteSpace(dto.LastName) ? u.LastName : dto.LastName.Trim();
                u.Email = string.IsNullOrWhiteSpace(dto.Email) ? u.Email : dto.Email.Trim();
                u.Gender = string.IsNullOrWhiteSpace(dto.Gender) ? u.Gender : dto.Gender;
                u.Country = string.IsNullOrWhiteSpace(dto.Country) ? u.Country : dto.Country;
                u.Address = string.IsNullOrWhiteSpace(dto.Address) ? u.Address : dto.Address;
                u.State = string.IsNullOrWhiteSpace(dto.State) ? u.State : dto.State;
                u.City = string.IsNullOrWhiteSpace(dto.City) ? u.City : dto.City;

                if (!string.IsNullOrWhiteSpace(dto.Dob))
                {
                    if (!TryParseDob(dto.Dob, out var parsed))
                        return BadRequest("Invalid DOB. Use yyyy-MM-dd or dd/MM/yyyy.");
                    u.Dob = parsed;
                }
                else if (dto.DOB.HasValue)
                {
                    u.Dob = DateOnly.FromDateTime(dto.DOB.Value);
                }

                if (!string.IsNullOrWhiteSpace(dto.ProfileImagePath))
                    u.ProfileImagePath = dto.ProfileImagePath;

                await _context.SaveChangesAsync();
                return Ok("Updated Successfully");
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Update failed: {ex.Message}");
            }
        }

        [HttpDelete("{id:int}")]
        public async Task<IActionResult> DeleteUsersRegister(int id)
        {
            try
            {
                var exists = await _context.UsersRegisters.AsNoTracking().AnyAsync(x => x.UserId == id);
                if (!exists)
                    return NotFound($"User with id {id} not found.");

                int affected = await _context.Database.ExecuteSqlRawAsync(
                    "DELETE FROM dbo.Users_Register WHERE UserID = {0}", id);

                if (affected <= 0)
                    return StatusCode(500, $"Raw delete executed but affected rows = {affected}.");

                return Ok("Deleted Successfully (raw).");
            }
            catch (DbUpdateException dbEx)
            {
                string inner = dbEx.InnerException?.Message ?? dbEx.Message;
                string stack = dbEx.StackTrace ?? "";
                return StatusCode(500, $"Delete failed (DbUpdateException): {inner}\nStackTrace:\n{stack}");
            }
            catch (Exception ex)
            {
                string inner = ex.InnerException?.Message ?? ex.Message;
                string stack = ex.StackTrace ?? "";
                return StatusCode(500, $"Delete failed (Exception): {inner}\nStackTrace:\n{stack}");
            }
        }
        #endregion
    }

    #region DTOs / Requests
    public class RegisterRequest
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string Email { get; set; } = "";
        public string Password { get; set; } = "";
        public string? Gender { get; set; }
        public string? Dob { get; set; }
        public string? Country { get; set; }
        public string? Address { get; set; }
        public string? ProfileImagePath { get; set; }
        public bool IsTermsAccepted { get; set; }
        public string? State { get; set; }
        public string? City { get; set; }
    }

    public class LoginRequest
    {
        public string Email { get; set; } = "";
        public string Password { get; set; } = "";
    }

    public class UserDto
    {
        public int UserID { get; set; }
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public string? Gender { get; set; }
        public DateTime? DOB { get; set; }
        public string? Country { get; set; }
        public string? Address { get; set; }
        public string? ProfileImagePath { get; set; }
        public string? State { get; set; }
        public string? City { get; set; }
    }

    public class UpdateUserDto
    {
        public string? FirstName { get; set; }
        public string? LastName { get; set; }
        public string? Email { get; set; }
        public string? Gender { get; set; }
        public string? Dob { get; set; }
        public DateTime? DOB { get; set; }
        public string? Country { get; set; }
        public string? Address { get; set; }
        public string? ProfileImagePath { get; set; }
        public string? State { get; set; }
        public string? City { get; set; }
    }

    public class SendResetDto
    {
        public string Email { get; set; } = "";
    }

    public class ResetPasswordDto
    {
        public string Token { get; set; } = "";
        public string NewPassword { get; set; } = "";
    }
    #endregion
}


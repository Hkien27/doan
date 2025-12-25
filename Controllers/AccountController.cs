using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecondHandSharing.Data;
using SecondHandSharing.Models;
using SecondHandSharing.Models.ViewModels;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace SecondHandSharing.Controllers
{
    public class AccountController : Controller
    {
        private readonly ApplicationDbContext _context;
        private readonly IWebHostEnvironment _env;

        public AccountController(ApplicationDbContext context, IWebHostEnvironment env)
        {
            _context = context;
            _env = env;
        }

        // ========== ĐĂNG KÝ ==========
        [HttpGet]
        public IActionResult Register() => View();

        [HttpPost]
        public IActionResult Register(User model)
        {
            if (ModelState.IsValid)
            {
                if (_context.Users.Any(u => u.Email == model.Email))
                {
                    ViewBag.Error = "Email đã tồn tại!";
                    return View(model);
                }

                model.PasswordHash = HashPassword(model.PasswordHash);
                // PhoneNumber, AvatarPath đã nằm trong model
                if (string.IsNullOrEmpty(model.AvatarPath))
                    model.AvatarPath = "/images/avatar_default.png";

                _context.Users.Add(model);
                _context.SaveChanges();

                TempData["Success"] = "Đăng ký thành công! Mời đăng nhập.";
                return RedirectToAction("Login");
            }
            return View(model);
        }

        // ========== ĐĂNG NHẬP ==========
        [HttpGet]
        public IActionResult Login() => View();

        [HttpPost]
        [HttpPost]
public async Task<IActionResult> Login(string email, string password)
{
    var hashed = HashPassword(password);
    var user = _context.Users.FirstOrDefault(u => u.Email == email && u.PasswordHash == hashed);

    if (user == null)
    {
        ViewBag.Error = "Sai email hoặc mật khẩu!";
        return View();
    }

    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
        new Claim(ClaimTypes.Name, user.FullName ?? ""),
        new Claim(ClaimTypes.Email, user.Email),
        new Claim(ClaimTypes.Role, user.Role?.ToUpper() ?? "USER"),
        // ⭐ QUAN TRỌNG: claim AvatarPath
        new Claim("AvatarPath", string.IsNullOrEmpty(user.AvatarPath)
                                ? "/images/avatar_default.png"
                                : user.AvatarPath)
    };

    var claimsIdentity = new ClaimsIdentity(
        claims,
        CookieAuthenticationDefaults.AuthenticationScheme
    );

    await HttpContext.SignInAsync(
        CookieAuthenticationDefaults.AuthenticationScheme,
        new ClaimsPrincipal(claimsIdentity),
        new AuthenticationProperties
        {
            IsPersistent = true,
            ExpiresUtc = DateTime.UtcNow.AddMinutes(60)
        });

    if (user.Role != null && user.Role.ToUpper() == "ADMIN")
        return RedirectToAction("Dashboard", "Admin");

    return RedirectToAction("Index", "Item");
}


        // ========== TRANG PROFILE (GET) ==========
        [Authorize]
        [HttpGet]
        public IActionResult Profile()
        {
            int userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
            var user = _context.Users.FirstOrDefault(u => u.UserId == userId);

            if (user == null) return NotFound();

            var vm = new UserAccountViewModel
            {
                UserId = user.UserId,
                FullName = user.FullName,
                Email = user.Email,
                PhoneNumber = user.PhoneNumber,
                AvatarPath = string.IsNullOrEmpty(user.AvatarPath)
                                ? "/images/avatar_default.png"
                                : user.AvatarPath
            };

            return View(vm);
        }

        // ========== CẬP NHẬT THÔNG TIN + AVATAR ==========
        [Authorize]
        [HttpPost]
        public async Task<IActionResult> UpdateInfo(UserAccountViewModel model)
        {
            int userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
            var user = _context.Users.FirstOrDefault(u => u.UserId == userId);

            if (user == null) return NotFound();

            if (!ModelState.IsValid)
            {
                TempData["ErrorInfo"] = "Dữ liệu không hợp lệ!";
                return RedirectToAction("Profile");
            }

            // Cập nhật thông tin cơ bản
            user.FullName = model.FullName;
            user.PhoneNumber = model.PhoneNumber;

            // ====== UPLOAD AVATAR NẾU CÓ ======
            if (model.AvatarFile != null && model.AvatarFile.Length > 0)
            {
                var uploadFolder = Path.Combine(_env.WebRootPath, "uploads", "avatars");
                if (!Directory.Exists(uploadFolder))
                    Directory.CreateDirectory(uploadFolder);

                var fileName = Guid.NewGuid().ToString() + Path.GetExtension(model.AvatarFile.FileName);
                var filePath = Path.Combine(uploadFolder, fileName);

                using (var stream = new FileStream(filePath, FileMode.Create))
                {
                    await model.AvatarFile.CopyToAsync(stream);
                }

                user.AvatarPath = "/uploads/avatars/" + fileName;
            }

            _context.SaveChanges();

            TempData["SuccessInfo"] = "Cập nhật thông tin thành công!";
            return RedirectToAction("Profile");
        }

        // ========== ĐỔI MẬT KHẨU ==========
        [Authorize]
        [HttpPost]
        public IActionResult ChangePassword(UserAccountViewModel model)
        {
            int userId = int.Parse(User.FindFirst(ClaimTypes.NameIdentifier)!.Value);
            var user = _context.Users.FirstOrDefault(u => u.UserId == userId);

            if (user == null) return NotFound();

            // Kiểm tra mật khẩu hiện tại
            var oldHashed = HashPassword(model.CurrentPassword ?? "");
            if (oldHashed != user.PasswordHash)
            {
                TempData["ErrorPassword"] = "Mật khẩu hiện tại không đúng!";
                return RedirectToAction("Profile");
            }

            if (string.IsNullOrWhiteSpace(model.NewPassword))
            {
                TempData["ErrorPassword"] = "Mật khẩu mới không được để trống!";
                return RedirectToAction("Profile");
            }

            // Đổi mật khẩu
            user.PasswordHash = HashPassword(model.NewPassword);
            _context.SaveChanges();

            TempData["SuccessPassword"] = "Đổi mật khẩu thành công!";
            return RedirectToAction("Profile");
        }

        // ========== ĐĂNG XUẤT ==========
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login");
        }

        // ========== ACCESS DENIED ==========
        public IActionResult AccessDenied() => View();

        // ========== HÀM BĂM MẬT KHẨU ==========
        private string HashPassword(string password)
        {
            using var sha = SHA256.Create();
            var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(password));
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }
    }
}

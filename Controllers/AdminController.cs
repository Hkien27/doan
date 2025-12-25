using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecondHandSharing.Data;
using SecondHandSharing.Models;

namespace SecondHandSharing.Controllers
{
    [Authorize(Roles = "ADMIN")]   // 🔒 chỉ admin truy cập
    public class AdminController : Controller
    {
        private readonly ApplicationDbContext _context;

        public AdminController(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<IActionResult> Dashboard()
        {
            var vm = new AdminDashboardViewModel
            {
                TotalUsers = await _context.Users.CountAsync(),
                TotalAdmins = await _context.Users.CountAsync(u => u.Role.ToUpper() == "ADMIN"),
                TotalItems = await _context.Items.CountAsync(),
                TotalActiveItems = await _context.Items.CountAsync(i => i.Status == "Đang bán"),
                TotalFavorites = _context.Favorites != null
                    ? await _context.Favorites.CountAsync()
                    : 0,
                TotalViewHistories = _context.ViewHistories != null
                    ? await _context.ViewHistories.CountAsync()
                    : 0,
                LatestUsers = await _context.Users
                    .OrderByDescending(u => u.CreatedAt)
                    .Take(5)
                    .ToListAsync(),
                LatestItems = await _context.Items
                    .Include(i => i.User)
                    .OrderByDescending(i => i.CreatedAt)
                    .Take(5)
                    .ToListAsync()
            };

            return View(vm);
        }
         public async Task<IActionResult> PendingItems()
    {
        var items = await _context.Items
            .Include(i => i.User)
            .Where(i => i.Status == "Chờ duyệt")
            .OrderByDescending(i => i.CreatedAt)
            .ToListAsync();

        return View(items);
    }

    // Duyệt tin
    [HttpPost]
    public async Task<IActionResult> ApproveItem(int id)
    {
        var item = await _context.Items.FindAsync(id);
        if (item == null) return NotFound();

        item.Status = "Đã duyệt";
        await _context.SaveChangesAsync();

        TempData["Success"] = "Đã duyệt tin.";
        return RedirectToAction("PendingItems");
    }

    // Từ chối tin
    [HttpPost]
    public async Task<IActionResult> RejectItem(int id)
    {
        var item = await _context.Items.FindAsync(id);
        if (item == null) return NotFound();

        item.Status = "Bị từ chối";
        await _context.SaveChangesAsync();

        TempData["Success"] = "Đã từ chối tin.";
        return RedirectToAction("PendingItems");
    }
    }
}

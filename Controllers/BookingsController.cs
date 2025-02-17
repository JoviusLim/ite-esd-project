using ESD_Jovius_Project.Data;
using ESD_Jovius_Project.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ESD_Jovius_Project.Controllers
{
    [Authorize]
    [Route("api/bookings")]
    [ApiController]

    public class BookingsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public BookingsController(ApplicationDbContext context)
        {
            _context = context;
        }

        [Authorize(Roles = UserRoles.Admin)]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Booking>>> GetBookings()
        {
            return await _context.Bookings.ToListAsync();
        }
    }
}
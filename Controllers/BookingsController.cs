using ESD_Jovius_Project.Data;
using ESD_Jovius_Project.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace ESD_Jovius_Project.Controllers
{
    [Authorize(Roles = UserRoles.Member + "," + UserRoles.Admin)]
    [Route("api/bookings")]
    [ApiController]

    public class BookingsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public BookingsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: api/bookings (Get all bookings)
        [HttpGet]
        public async Task<ActionResult<IEnumerable<Booking>>> GetBookings()
        {
            return await _context.Bookings.ToListAsync();
        }

        // GET: api/bookings/5 (Get booking by id)
        [HttpGet("{id}")]
        public async Task<ActionResult<Booking>> GetBooking(int id)
        {
            var booking = await _context.Bookings.FindAsync(id);

            if (booking == null)
            {
                return NotFound();
            }

            return booking;
        }

        // POST: api/bookings (Create a booking)
        [HttpPost]
        public async Task<ActionResult<Booking>> PostBooking([FromBody] BookingCreateModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var booking = new Booking
            {
                FacilityDescription = model.FacilityDescription ?? String.Empty,
                BookingDateFrom = model.BookingDateFrom,
                BookingDateTo = model.BookingDateTo,
                BookedBy = model.BookedBy ?? String.Empty,
                BookingStatus = model.BookingStatus

            };

            _context.Bookings.Add(booking);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetBooking), new { id = booking.BookingId }, booking);
        }

        // PUT: api/bookings/5 (Update a booking)
        [HttpPut("{id}")]
        public async Task<IActionResult> PutBooking(int id, [FromBody] BookingCreateModel model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var booking = await _context.Bookings.FindAsync(id);

            if (booking == null)
            {
                return NotFound();
            }

            booking.FacilityDescription = model.FacilityDescription ?? String.Empty;
            booking.BookingDateFrom = model.BookingDateFrom;
            booking.BookingDateTo = model.BookingDateTo;
            booking.BookedBy = model.BookedBy ?? String.Empty;
            booking.BookingStatus = model.BookingStatus;

            await _context.SaveChangesAsync();

            return Ok(new Response { Status = "Success", Message = "Booking updated successfully!" });
        }

        // DELETE: api/bookings/5 (Delete a booking)
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteBooking(int id)
        {
            var booking = await _context.Bookings.FindAsync(id);

            if (booking == null)
            {
                return NotFound();
            }

            _context.Bookings.Remove(booking);
            await _context.SaveChangesAsync();

            return Ok(new Response { Status = "Success", Message = "Booking deleted successfully!" });
        }
    }
}
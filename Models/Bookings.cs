using System.ComponentModel.DataAnnotations;

namespace ESD_Jovius_Project.Models
{
    public class Booking
    {
        [Key]
        public int BookingId { get; set; }
        [StringLength(255)]
        public required string FacilityDescription { get; set; }
        public required DateTime BookingDateFrom { get; set; }
        public required DateTime BookingDateTo { get; set; }
        [StringLength(255)]
        public required string BookedBy { get; set; }
        [StringLength(50)]
        public required string BookingStatus { get; set; } = "Pending";
    }
}
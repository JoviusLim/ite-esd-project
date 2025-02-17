namespace ESD_Jovius_Project.Models
{
    public class BookingCreateModel
    {
        public string? FacilityDescription { get; set; }
        public DateTime BookingDateFrom { get; set; }
        public DateTime BookingDateTo { get; set; }
        public string? BookedBy { get; set; }
        public string BookingStatus { get; set; } = "Pending";
    }
}
using System.ComponentModel.DataAnnotations;

namespace EMS.BaseLibrary.DTOs
{
    public class Register : AccountBase
    {
        [Required]
        [MinLength(1)]
        [MaxLength(100)]
        public string? Fullname { get; set; }

        [Required]
        [DataType(DataType.Password)]
        [Compare(nameof(Password))]
        public string? ConfirmPassword { get; set; }
    }
}

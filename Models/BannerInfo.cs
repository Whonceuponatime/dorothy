namespace Dorothy.Models
{
    public record BannerInfo(
        int Port,
        string? RawBanner,
        string? IdentifiedService,
        string? IdentifiedVersion,
        TlsInfo? Tls = null);
}

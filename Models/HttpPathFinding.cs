namespace Dorothy.Models
{
    /// <summary>
    /// One result row from HttpPathDiscoveryService — a path we probed and
    /// got a non-404 response for. Status codes worth surfacing: 200/301/302/401/403.
    /// </summary>
    public record HttpPathFinding(
        string Path,
        int StatusCode,
        string? Title,
        long ContentLength);
}

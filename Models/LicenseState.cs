namespace Dorothy.Models
{
    /// <summary>
    /// Tri-state license result, replacing the prior boolean is/isn't licensed.
    ///
    /// Active   — server validated within the validity window OR validity is
    ///            unlimited (validity_period_days null/0). App fully usable.
    /// Stale    — offline beyond validity_period_days but within 2× of it.
    ///            App fully usable, yellow banner asks the user to refresh.
    /// Expired  — server explicitly revoked OR offline beyond 2× validity.
    ///            App blocks; License Validation overlay shown.
    /// </summary>
    public enum LicenseState
    {
        Active  = 0,
        Stale   = 1,
        Expired = 2
    }
}

namespace NuGetDefense.Configuration
{
    public enum Severity
    {
        /// <summary>
        ///     CVSS3 score 9.0 - 10.0
        /// </summary>
        Critical,

        /// <summary>
        ///     CVSS3 score 7.0 - 8.9
        /// </summary>
        High,

        /// <summary>
        ///     CVSS3 score 4.0 - 6.9
        /// </summary>
        Medium,

        /// <summary>
        ///     CVSS3 score 0.1 - 3.9
        /// </summary>
        Low,

        /// <summary>
        ///     CVSS3 Score of 0.0
        /// </summary>
        None,

        /// <summary>
        ///     Any CVSS3 Score
        /// </summary>
        Any
    }
}
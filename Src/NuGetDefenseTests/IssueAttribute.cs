using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NuGetDefenseTests
{
    /// <summary>
    /// Tags a test a validating behaviour observed in the supplied issue.
    /// </summary>
    [AttributeUsage(AttributeTargets.Method)]
    internal class IssueAttribute : Attribute
    {
        public int IssueId { get; }

        public IssueAttribute(int issueId)
        {
            IssueId = issueId;    
        }
    }
}

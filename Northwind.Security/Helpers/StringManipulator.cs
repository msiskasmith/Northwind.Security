using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Northwind.Security.Helpers
{
    public static class StringManipulator
    {
        public static string RemoveExtraSpaces(string item)
        {
            item = item.Trim();

            item = Regex.Replace(item, @"\s+", " ");

            return item;
        }
    }
}

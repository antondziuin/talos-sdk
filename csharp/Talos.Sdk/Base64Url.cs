using System;

namespace Talos.Sdk
{
    internal static class Base64Url
    {
        public static string Encode(byte[] bytes)
        {
            return Convert.ToBase64String(bytes)
                .TrimEnd('=')
                .Replace('+', '-')
                .Replace('/', '_');
        }

        public static byte[] Decode(string s)
        {
            string t = s.Replace('-', '+').Replace('_', '/');
            switch (t.Length % 4)
            {
                case 2: t += "=="; break;
                case 3: t += "="; break;
            }
            return Convert.FromBase64String(t);
        }
    }
}

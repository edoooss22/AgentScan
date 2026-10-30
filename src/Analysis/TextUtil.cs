using System.Text;

namespace AgentScan.Analysis;

internal static class StringExtract
{
    public static List<string> Ascii(ReadOnlySpan<byte> data, int min)
    {
        var res = new List<string>();
        var sb = new StringBuilder();
        foreach (byte b in data)
        {
            if (b >= 0x20 && b < 0x7F) sb.Append((char)b);
            else
            {
                if (sb.Length >= min) res.Add(sb.ToString());
                sb.Clear();
            }
        }
        if (sb.Length >= min) res.Add(sb.ToString());
        return res;
    }
}

internal static class HexDump
{
    public static string Format(ReadOnlySpan<byte> data, ulong baseAddr, int perLine = 16)
    {
        var sb = new StringBuilder();
        for (int i = 0; i < data.Length; i += perLine)
        {
            int n = Math.Min(perLine, data.Length - i);
            sb.Append($"{baseAddr + (ulong)i:X16}  ");
            for (int j = 0; j < perLine; j++)
                sb.Append(j < n ? $"{data[i + j]:X2} " : "   ");
            sb.Append(' ');
            for (int j = 0; j < n; j++)
            {
                byte b = data[i + j];
                sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
            }
            sb.AppendLine();
        }
        return sb.ToString().TrimEnd();
    }
}

using System.Text;

namespace AgentScan.Core;

internal static class JavaNames
{
    public const string EscapePrefix = "\\u";

    public static string DecodeModifiedUtf8(ReadOnlySpan<byte> b)
    {
        var sb = new StringBuilder(b.Length);
        for (int i = 0; i < b.Length; i++)
        {
            byte c = b[i];
            int cp;
            if (c < 0x80) cp = c;
            else if ((c & 0xE0) == 0xC0 && i + 1 < b.Length)
            {
                cp = ((c & 0x1F) << 6) | (b[i + 1] & 0x3F);
                i += 1;
            }
            else if ((c & 0xF0) == 0xE0 && i + 2 < b.Length)
            {
                cp = ((c & 0x0F) << 12) | ((b[i + 1] & 0x3F) << 6) | (b[i + 2] & 0x3F);
                i += 2;
            }
            else cp = c;

            if (cp is >= 0x20 and < 0x7F) sb.Append((char)cp);
            else sb.Append(EscapePrefix).Append(cp.ToString("X4"));
        }
        return sb.ToString();
    }

    public static bool HasNonAscii(string decoded) =>
        decoded.Contains(EscapePrefix, StringComparison.Ordinal);

    public static bool LooksLikeFreedMemory(string decoded)
    {
        if (decoded.Contains("\\u0000", StringComparison.Ordinal)) return true;

        int high = 0, escapes = 0;
        int i = 0;
        while ((i = decoded.IndexOf(EscapePrefix, i, StringComparison.Ordinal)) >= 0)
        {
            if (i + 6 > decoded.Length) break;
            escapes++;
            if (int.TryParse(decoded.AsSpan(i + 2, 4),
                    System.Globalization.NumberStyles.HexNumber, null, out int cp) &&
                cp is >= 0x80 and <= 0xFF) high++;
            i += 6;
        }
        return escapes > 0 && high * 2 >= escapes;
    }

    public static string DescribeCodePoints(string decoded)
    {
        var kinds = new SortedSet<string>(StringComparer.Ordinal);
        int i = 0;
        while ((i = decoded.IndexOf(EscapePrefix, i, StringComparison.Ordinal)) >= 0)
        {
            if (i + 6 > decoded.Length) break;
            if (!int.TryParse(decoded.AsSpan(i + 2, 4),
                    System.Globalization.NumberStyles.HexNumber, null, out int cp)) { i += 2; continue; }
            kinds.Add(Classify(cp));
            i += 6;
        }
        return kinds.Count == 0 ? "" : string.Join(", ", kinds);
    }

    private static string Classify(int cp) => cp switch
    {
        < 0x20 => "управляющий символ",
        0x7F => "управляющий символ",
        >= 0x0080 and <= 0x00FF => "латиница-1 (диакритика)",
        >= 0x0400 and <= 0x04FF => "кириллица (омоглифы латиницы)",
        >= 0x0370 and <= 0x03FF => "греческий (омоглифы латиницы)",
        >= 0x0590 and <= 0x08FF => "письмо справа налево",
        0x200B or 0x200C or 0x200D or 0xFEFF => "невидимый символ нулевой ширины",
        >= 0x200E and <= 0x200F => "метка направления письма",
        >= 0x2000 and <= 0x206F => "типографские пробелы и метки",
        >= 0x2100 and <= 0x214F => "буквоподобные знаки",
        >= 0x3000 and <= 0x303F => "японская пунктуация",
        >= 0x4E00 and <= 0x9FFF => "иероглифы",
        >= 0xE000 and <= 0xF8FF => "область частного использования",
        >= 0xFF00 and <= 0xFFEF => "полноширинные формы (омоглифы ASCII)",
        _ => $"иной блок Юникода (U+{cp:X4})",
    };
}

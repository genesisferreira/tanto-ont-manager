using System.Text;
using System.Text.Json;

namespace TantoOntManager.DeviceAdapters.Zte.Auth;

public static class F6201BJsObjectLiteral
{
    public static bool TryParseArray(string? js, out JsonDocument? document)
    {
        document = null;
        if (string.IsNullOrWhiteSpace(js))
        {
            return false;
        }

        try
        {
            document = JsonDocument.Parse(js);
            return true;
        }
        catch (JsonException)
        {
        }

        if (!TryConvert(js, out var json))
        {
            return false;
        }

        try
        {
            document = JsonDocument.Parse(json);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }

    public static bool TryConvert(string js, out string json)
    {
        var sb = new StringBuilder(js.Length + 32);
        var inSingle = false;
        var inDouble = false;
        var escaped = false;
        for (var i = 0; i < js.Length; i++)
        {
            var ch = js[i];
            if (escaped)
            {
                sb.Append(ch);
                escaped = false;
                continue;
            }

            if (ch == '\\' && (inSingle || inDouble))
            {
                sb.Append(ch);
                escaped = true;
                continue;
            }

            if (!inSingle && !inDouble && ch == '/' && i + 1 < js.Length)
            {
                if (js[i + 1] == '/')
                {
                    while (i < js.Length && js[i] != '\n')
                    {
                        i++;
                    }

                    continue;
                }

                if (js[i + 1] == '*')
                {
                    i += 2;
                    while (i + 1 < js.Length && !(js[i] == '*' && js[i + 1] == '/'))
                    {
                        i++;
                    }

                    i++;
                    continue;
                }
            }

            if (!inSingle && !inDouble && ch == '\'')
            {
                inSingle = true;
                sb.Append('"');
                continue;
            }

            if (inSingle && ch == '\'')
            {
                inSingle = false;
                sb.Append('"');
                continue;
            }

            if (inSingle && ch == '"')
            {
                sb.Append('\\').Append('"');
                continue;
            }

            if (!inSingle && ch == '"')
            {
                inDouble = !inDouble;
                sb.Append(ch);
                continue;
            }

            if (!inSingle && !inDouble && IsIdentStart(ch))
            {
                var start = i;
                i++;
                while (i < js.Length && IsIdentPart(js[i]))
                {
                    i++;
                }

                var ident = js[start..i];
                var j = i;
                while (j < js.Length && char.IsWhiteSpace(js[j]))
                {
                    j++;
                }

                if (j < js.Length && js[j] == ':')
                {
                    sb.Append('"').Append(ident).Append('"');
                }
                else
                {
                    sb.Append(ident);
                }

                i--;
                continue;
            }

            if (!inSingle && !inDouble && (ch == '}' || ch == ']'))
            {
                TrimTrailingComma(sb);
            }

            sb.Append(ch);
        }

        json = sb.ToString();
        return json.Length > 0;
    }

    private static void TrimTrailingComma(StringBuilder sb)
    {
        var i = sb.Length - 1;
        while (i >= 0 && char.IsWhiteSpace(sb[i]))
        {
            i--;
        }

        if (i >= 0 && sb[i] == ',')
        {
            sb.Length = i;
        }
    }

    private static bool IsIdentStart(char ch)
        => ch is '_' or (>= 'A' and <= 'Z') or (>= 'a' and <= 'z');

    private static bool IsIdentPart(char ch)
        => IsIdentStart(ch) || ch is >= '0' and <= '9';
}

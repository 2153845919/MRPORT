using System;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Documents;

namespace MRPORT.Services;

public class AnnouncementService
{
    private static readonly string AnnouncementUrl = "https://share.note.youdao.com/s/VB2TZZPc";

    public async Task<string> FetchAsync()
    {
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("MRPORT/1.0");
            var html = await client.GetStringAsync(AnnouncementUrl);
            return StripHtml(html);
        }
        catch (Exception ex)
        {
            return $"无法加载公告: {ex.Message}";
        }
    }

    private static string StripHtml(string html)
    {
        var sb = new StringBuilder();
        bool inTag = false;
        foreach (char c in html)
        {
            if (c == '<') inTag = true;
            else if (c == '>') inTag = false;
            else if (!inTag) sb.Append(c);
        }
        var text = sb.ToString().Trim();
        return string.IsNullOrWhiteSpace(text) ? html : text;
    }
}

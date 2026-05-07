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
    private static readonly string AnnouncementUrl = "https://luoke-1313441516.cos.ap-guangzhou.myqcloud.com/gongao.txt";

    public async Task<string> FetchAsync()
    {
        try
        {
            using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("MRPORT/1.0");
            var text = await client.GetStringAsync(AnnouncementUrl);
            return text.Trim();
        }
        catch (Exception ex)
        {
            return $"无法加载公告: {ex.Message}";
        }
    }

    // Text is fetched as plain text from the new URL - no HTML stripping needed
}

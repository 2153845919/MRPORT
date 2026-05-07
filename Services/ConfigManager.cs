using System;
using System.IO;
using Newtonsoft.Json;

namespace MRPORT.Services;

public class ConfigManager
{
    private static readonly string ConfigPath =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MRPORT", "config.json");

    public Models.AppConfig Load()
    {
        try
        {
            if (File.Exists(ConfigPath))
            {
                var json = File.ReadAllText(ConfigPath);
                return JsonConvert.DeserializeObject<Models.AppConfig>(json) ?? new();
            }
        }
        catch { }
        return new();
    }

    public void Save(Models.AppConfig config)
    {
        try
        {
            var dir = Path.GetDirectoryName(ConfigPath)!;
            Directory.CreateDirectory(dir);
            File.WriteAllText(ConfigPath, JsonConvert.SerializeObject(config, Formatting.Indented));
        }
        catch { }
    }
}

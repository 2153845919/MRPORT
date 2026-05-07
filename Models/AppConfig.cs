namespace MRPORT.Models;

public class AppConfig
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string LastRunTime { get; set; } = "";
    public string ServerAddress { get; set; } = "111.230.193.4";
    public int ServerPort { get; set; } = 21538;
    public int LatencyPort { get; set; } = 10012;
}

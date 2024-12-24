public interface IAttackLogger
{
    void LogInfo(string message);
    void LogError(string message);
    void LogWarning(string message);
} 
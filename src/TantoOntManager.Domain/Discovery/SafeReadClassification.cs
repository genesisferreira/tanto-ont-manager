namespace TantoOntManager.Domain.Discovery;

public enum SafeReadClassification
{
    SafeRead = 0,
    BlockedPotentialAction = 1,
    UnknownNotAccessed = 2,
    Duplicate = 3,
    Invalid = 4
}

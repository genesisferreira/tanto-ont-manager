using System.IO;
using System.Net;
using TantoOntManager.DeviceAdapters.Abstractions;
using TantoOntManager.Domain.Observation;

namespace TantoOntManager.App.Observation;

public sealed record ObservationLaunchRequest(
    IPAddress BoundAddress,
    Uri StartUri,
    IReadOnlyList<IsolatedObserverCookie> Cookies,
    string UserDataFolder);

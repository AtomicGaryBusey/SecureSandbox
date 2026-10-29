import Observation

@MainActor @Observable
final class NavigationState {
    var section: ControlSection? = .overview
    var selectedSessionID: String?
    var searchRequest = 0
}

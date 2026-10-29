#if DEBUG
import SwiftUI

@MainActor
private enum OverviewPreviewData {
    static func healthy() -> CatalogStore {
        let store = CatalogStore()
        store.status = HostStatus(
            schema: "secure-sandbox-host-status-v1",
            status: "verified",
            observed: .init(gateway: "running", research: "running", target: "running",
                            gatewayNet0: "connected"),
            reachability: .init(gateway: "reachable", research: "reachable", target: "reachable")
        )
        store.refreshedAt = Date()
        return store
    }

    static func degraded() -> CatalogStore {
        let store = CatalogStore()
        store.status = HostStatus(
            schema: "secure-sandbox-host-status-v1",
            status: "verified",
            observed: .init(gateway: "running", research: "running", target: "stopped",
                            gatewayNet0: "disconnected"),
            reachability: .init(gateway: "reachable", research: "reachable", target: "unreachable")
        )
        store.refreshedAt = Date()
        return store
    }

    static func stopped() -> CatalogStore {
        let store = CatalogStore()
        store.status = HostStatus(
            schema: "secure-sandbox-host-status-v1",
            status: "verified",
            observed: .init(gateway: "stopped", research: "stopped", target: "stopped",
                            gatewayNet0: "disconnected"),
            reachability: .init(gateway: "unreachable", research: "unreachable", target: "unreachable")
        )
        store.refreshedAt = Date()
        return store
    }

    static func unavailable() -> CatalogStore {
        let store = CatalogStore()
        store.errors["overview"] = "The host status is temporarily unavailable."
        return store
    }
}

#Preview("Healthy stack") {
    OverviewView(store: OverviewPreviewData.healthy())
        .frame(width: 1000, height: 650)
}

#Preview("Degraded stack") {
    OverviewView(store: OverviewPreviewData.degraded())
        .frame(width: 1000, height: 650)
}

#Preview("Stopped stack") {
    OverviewView(store: OverviewPreviewData.stopped())
        .frame(width: 1000, height: 650)
}

#Preview("Status unavailable") {
    OverviewView(store: OverviewPreviewData.unavailable())
        .frame(width: 1000, height: 650)
}
#endif

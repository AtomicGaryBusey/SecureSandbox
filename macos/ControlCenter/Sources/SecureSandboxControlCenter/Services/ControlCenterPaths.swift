import Darwin
import Foundation

enum ControlCenterPaths {
    static let repository = NSHomeDirectory() + "/SecureSandbox"

    static func hasLocalBridge() -> Bool {
        trustedFile(NSHomeDirectory(), directory: true)
            && trustedFile(repository, directory: true)
            && trustedFile(repository + "/scripts", directory: true)
            && trustedFile(repository + "/scripts/control-center-api.py", directory: false)
            && trustedFile(repository + "/scripts/labctl", directory: false)
    }

    private static func trustedFile(_ path: String, directory: Bool) -> Bool {
        var metadata = stat()
        guard lstat(path, &metadata) == 0,
              metadata.st_uid == geteuid(),
              metadata.st_mode & mode_t(S_IFMT) == mode_t(directory ? S_IFDIR : S_IFREG),
              metadata.st_mode & 0o022 == 0 else { return false }
        return directory || metadata.st_nlink == 1
    }
}

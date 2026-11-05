public enum NativeOperationDeadlinePolicy {
    // Native stack sign-in has the longest non-deployment authorization
    // chain: root broker (1,440) < wrapper (1,500) < Control Center API
    // (1,560) < the Swift bridge.  The bridge uses this conservative outer
    // bound for every native-stack action; shorter inner actions still own
    // and report their own deadlines.
    public static let nativeStackActionBridgeSeconds = 1_620
    public static let rootProtectedMutationSeconds = 3_900
    public static let directBrokerClientSeconds = 4_020
    public static let authorizationClientSeconds = 4_140
    public static let controlCenterAPIClientSeconds = 4_200
    public static let controlCenterBridgeSeconds = 4_320
}

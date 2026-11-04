import Darwin
import SecureSandboxNativeCredentialHelper

// Deliberately no argv or stdin command surface. All requests enter through
// the signed XPC transport after its message-bound peer requirement succeeds.
exit(SecureSandboxNativeCredentialXPCServiceMain.run())

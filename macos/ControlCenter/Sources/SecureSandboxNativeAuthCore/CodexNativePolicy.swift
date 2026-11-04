import Foundation

public enum CodexNativePolicy {
    public static let providerID = "openai_chatgpt_plan"
    public static let clientName = "SecureSandbox"
    public static let clientTitle = "SecureSandbox"
    public static let admittedModels: Set<String> = ["gpt-6-sol", "gpt-6-luna"]
    public static let cyberAccessProgram = "daybreakBlue"
    public static let reasoningEffort = "high"
    public static let minimumAppServerVersion = "0.163.0"
    public static let workspace = "/home/agent/research-workspace"
    public static let isolatedHome = "/var/lib/secure-sandbox/native-vendor/openai/codex-home"

    public static func appServerArguments(model: String) throws -> [String] {
        guard admittedModels.contains(model) else { throw NativeAuthError.invalidPolicy("Codex model") }
        return [
            "app-server", "--strict-config", "--listen", "stdio://",
            "-c", #"model_provider="openai_chatgpt_plan""#,
            "-c", #"model_providers.openai_chatgpt_plan.name="ChatGPT plan""#,
            "-c", #"model_providers.openai_chatgpt_plan.base_url="https://api.openai.com/v1""#,
            "-c", #"model_providers.openai_chatgpt_plan.env_key="ACCESS_TOKEN""#,
            "-c", #"model_providers.openai_chatgpt_plan.wire_api="responses""#,
            "-c", "model_providers.openai_chatgpt_plan.requires_openai_auth=false",
            "-c", "model_providers.openai_chatgpt_plan.supports_websockets=false",
            "-c", "sandbox_workspace_write.network_access=false",
            "-c", #"shell_environment_policy.inherit="none""#,
            "-c", "shell_environment_policy.ignore_default_excludes=false",
            "-c", #"shell_environment_policy.exclude=["ACCESS_TOKEN","OPENAI_API_KEY","OPENAI_ACCESS_TOKEN","OPENAI_REFRESH_TOKEN","CHATGPT_ACCESS_TOKEN","CHATGPT_REFRESH_TOKEN"]"#,
            "-c", "shell_environment_policy.set={}",
            "-c", "mcp_servers={}",
            "-c", #"history.persistence="none""#,
            "-c", #"projects."/home/agent/research-workspace".trust_level="untrusted""#,
            "-c", "skills.bundled.enabled=false",
            "-c", "skills.include_instructions=false",
            "-c", "project_doc_max_bytes=0",
            "-c", "project_doc_fallback_filenames=[]",
            "-c", "tools.web_search=false",
            "-c", "features.plugins=false",
            "-c", "features.remote_plugin=false",
            "-c", "features.plugin_discovery_prefetch=false",
            "-c", "features.plugin_sharing=false",
            "-c", "features.recommended_plugins=false",
            "-c", "features.apps=false",
            "-c", "features.enable_mcp_apps=false",
            "-c", "features.hooks=false",
            "-c", "features.multi_agent=false",
            "-c", "features.multi_agent_v2=false",
            "-c", "features.browser_use=false",
            "-c", "features.browser_use_external=false",
            "-c", "features.browser_use_full_cdp_access=false",
            "-c", "features.in_app_browser=false",
            "-c", "features.image_generation=false",
            "-c", "features.workspace_dependencies=false",
            "-c", "features.skill_search=false",
            "-c", "features.skill_catalog_deltas=false",
            "-c", "features.skill_mcp_dependency_install=false",
            "-c", "features.skip_host_skill_discovery=true",
            "-c", #"model_reasoning_effort="high""#,
            "-c", #"model="\#(model)""#,
        ]
    }

    public static func initializeRequest(id: Int, version: String) throws -> Data {
        guard id > 0, appServerVersionIsAdmitted(version) else {
            throw NativeAuthError.invalidPolicy("Codex client identity")
        }
        return try canonicalJSON([
            "id": id,
            "method": "initialize",
            "params": [
                "clientInfo": ["name": clientName, "title": clientTitle, "version": version],
                "capabilities": ["experimentalApi": true],
            ],
        ])
    }

    public static func modelListRequest(id: Int) throws -> Data {
        guard id > 0 else { throw NativeAuthError.invalidPolicy("Codex model list") }
        return try canonicalJSON([
            "id": id,
            "method": "model/list",
            "params": ["cursor": NSNull(), "includeHidden": true, "limit": 100],
        ])
    }

    public static func verifyModelListResponse(
        _ data: Data, requestID: Int, selectedModel: String
    ) throws {
        guard requestID > 0, admittedModels.contains(selectedModel),
              let object = exactObject(data, maximum: 1_048_576),
              Set(object.keys) == ["id", "result"],
              object["id"] as? Int == requestID,
              let result = object["result"] as? [String: Any],
              Set(result.keys) == ["data", "nextCursor"],
              result["nextCursor"] is NSNull,
              let models = result["data"] as? [[String: Any]],
              (1...100).contains(models.count) else {
            throw NativeAuthError.invalidToken("Codex model catalog")
        }
        let selected = models.filter { $0["model"] as? String == selectedModel }
        guard selected.count == 1,
              let access = selected[0]["availableAccessPrograms"] as? [String: Any],
              Set(access.keys) == ["cyber"],
              let cyber = access["cyber"] as? [String],
              Set(cyber).count == cyber.count,
              cyber.allSatisfy({ ["standard", "daybreakBlue", "daybreakRed"].contains($0) }),
              cyber.contains(cyberAccessProgram) else {
            throw NativeAuthError.invalidToken("Codex Daybreak model entitlement")
        }
    }

    public static func threadStartRequest(id: Int, model: String) throws -> Data {
        guard id > 0, admittedModels.contains(model) else {
            throw NativeAuthError.invalidPolicy("Codex thread")
        }
        return try canonicalJSON([
            "id": id, "method": "thread/start", "params": [
                "model": model,
                "modelProvider": providerID,
                "allowProviderModelFallback": false,
                "cwd": workspace,
                "runtimeWorkspaceRoots": [workspace],
                "approvalPolicy": "never",
                "sandbox": "read-only",
                "environments": [],
                "dynamicTools": [],
                "selectedCapabilityRoots": [],
                "daybreakEnabled": true,
                "ephemeral": false,
            ],
        ])
    }

    public static func turnStartRequest(
        id: Int, threadID: String, input: String, model: String
    ) throws -> Data {
        guard admittedModels.contains(model) else { throw NativeAuthError.invalidPolicy("Codex model") }
        guard id > 0, (1...512).contains(threadID.utf8.count),
              threadID.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) }),
              (1...1_048_576).contains(input.utf8.count) else {
            throw NativeAuthError.invalidPolicy("Codex turn")
        }
        return try canonicalJSON([
            "id": id,
            "method": "turn/start",
            "params": [
                "threadId": threadID,
                "input": [["type": "text", "text": input]],
                "cyberAccessProgram": cyberAccessProgram,
                "model": model,
                "effort": reasoningEffort,
                "cwd": workspace,
                "runtimeWorkspaceRoots": [workspace],
                "approvalPolicy": "never",
                "environments": [],
                "disabledPluginIds": [],
            ],
        ])
    }

    public static func capabilityReadbackRequests(startingAt id: Int) throws -> [Data] {
        guard id > 0, id <= Int.max - 3 else {
            throw NativeAuthError.invalidPolicy("Codex capability readback")
        }
        return try [
            canonicalJSON([
                "id": id, "method": "skills/list",
                "params": ["cwds": [workspace], "forceReload": true],
            ]),
            canonicalJSON(["id": id + 1, "method": "plugin/list", "params": [:]]),
            canonicalJSON(["id": id + 2, "method": "hooks/list", "params": [:]]),
            canonicalJSON(["id": id + 3, "method": "mcpServerStatus/list", "params": [:]]),
        ]
    }

    public static func verifyCapabilityReadback(
        skills: Data,
        plugins: Data,
        hooks: Data,
        mcpServers: Data,
        startingAt id: Int
    ) throws {
        guard id > 0, id <= Int.max - 3,
              let skillsObject = exactObject(skills, maximum: 262_144),
              Set(skillsObject.keys) == ["id", "result"],
              skillsObject["id"] as? Int == id,
              let skillsResult = skillsObject["result"] as? [String: Any],
              Set(skillsResult.keys) == ["data"],
              let skillEntries = skillsResult["data"] as? [[String: Any]],
              skillEntries.count == 1,
              Set(skillEntries[0].keys) == ["cwd", "skills", "errors"],
              skillEntries[0]["cwd"] as? String == workspace,
              let skillList = skillEntries[0]["skills"] as? [Any], skillList.isEmpty,
              let skillErrors = skillEntries[0]["errors"] as? [Any], skillErrors.isEmpty,
              let pluginObject = exactObject(plugins, maximum: 262_144),
              Set(pluginObject.keys) == ["id", "result"],
              pluginObject["id"] as? Int == id + 1,
              let pluginResult = pluginObject["result"] as? [String: Any],
              Set(pluginResult.keys) == ["marketplaces", "marketplaceLoadErrors", "featuredPluginIds"],
              (pluginResult["marketplaces"] as? [Any])?.isEmpty == true,
              (pluginResult["marketplaceLoadErrors"] as? [Any])?.isEmpty == true,
              (pluginResult["featuredPluginIds"] as? [Any])?.isEmpty == true,
              let hooksObject = exactObject(hooks, maximum: 262_144),
              Set(hooksObject.keys) == ["id", "result"],
              hooksObject["id"] as? Int == id + 2,
              let hooksResult = hooksObject["result"] as? [String: Any],
              Set(hooksResult.keys) == ["data"],
              let hookEntries = hooksResult["data"] as? [[String: Any]],
              hookEntries.count == 1,
              Set(hookEntries[0].keys) == ["cwd", "hooks", "warnings", "errors"],
              hookEntries[0]["cwd"] as? String == workspace,
              (hookEntries[0]["hooks"] as? [Any])?.isEmpty == true,
              (hookEntries[0]["warnings"] as? [Any])?.isEmpty == true,
              (hookEntries[0]["errors"] as? [Any])?.isEmpty == true,
              let mcpObject = exactObject(mcpServers, maximum: 262_144),
              Set(mcpObject.keys) == ["id", "result"],
              mcpObject["id"] as? Int == id + 3,
              let mcpResult = mcpObject["result"] as? [String: Any],
              Set(mcpResult.keys) == ["data", "nextCursor"],
              (mcpResult["data"] as? [Any])?.isEmpty == true,
              mcpResult["nextCursor"] is NSNull else {
            throw NativeAuthError.invalidToken("Codex capability authority")
        }
    }

    public static func isCapabilityInvalidation(_ data: Data) throws -> Bool {
        guard let object = exactObject(data, maximum: 65_536),
              let method = object["method"] as? String else {
            throw NativeAuthError.invalidToken("Codex notification")
        }
        return method == "skills/changed"
    }

    @available(*, unavailable, message: "Every native turn must name its exact admitted model")
    public static func turnStartRequest(id: Int, threadID: String, input: String) throws -> Data {
        fatalError()
    }

    public static func verifyThreadStartResponse(
        _ data: Data, requestID: Int, model: String
    ) throws -> String {
        guard requestID > 0, admittedModels.contains(model), data.count <= 262_144,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["id"] as? Int == requestID,
              object["error"] == nil,
              let result = object["result"] as? [String: Any],
              result["model"] as? String == model,
              result["modelProvider"] as? String == providerID,
              result["cwd"] as? String == workspace,
              result["approvalPolicy"] as? String == "never",
              result["approvalsReviewer"] as? String == "user",
              result["reasoningEffort"] as? String == reasoningEffort,
              result["multiAgentMode"] as? String == "explicitRequestOnly",
              result["activePermissionProfile"] is NSNull,
              result["serviceTier"] is NSNull,
              result["runtimeWorkspaceRoots"] as? [String] == [],
              result["instructionSources"] as? [String] == [],
              result["disabledPluginIds"] as? [String] == [],
              let sandbox = result["sandbox"] as? [String: Any],
              Set(sandbox.keys) == ["type", "networkAccess"],
              sandbox["type"] as? String == "readOnly",
              sandbox["networkAccess"] as? Bool == false,
              let thread = result["thread"] as? [String: Any],
              let threadID = thread["id"] as? String,
              (1...512).contains(threadID.utf8.count),
              thread["model"] as? String == model,
              thread["modelProvider"] as? String == providerID,
              thread["reasoningEffort"] as? String == reasoningEffort,
              (thread["environments"] as? [Any])?.isEmpty == true,
              thread["daybreakEnabled"] as? Bool == true,
              thread["cwd"] as? String == workspace,
              thread["ephemeral"] as? Bool == false else {
            throw NativeAuthError.invalidToken("Codex thread authority")
        }
        return threadID
    }

    public static func verifyTurnStartResponse(
        _ data: Data, requestID: Int
    ) throws -> String {
        guard requestID > 0, data.count <= 262_144,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["id"] as? Int == requestID,
              object["error"] == nil,
              let result = object["result"] as? [String: Any],
              let turn = result["turn"] as? [String: Any],
              let turnID = turn["id"] as? String,
              (1...512).contains(turnID.utf8.count),
              turn["status"] as? String == "inProgress" else {
            throw NativeAuthError.invalidToken("Codex turn start")
        }
        return turnID
    }

    public static func verifyCompletedTurn(
        _ data: Data, threadID: String, turnID: String
    ) throws {
        guard data.count <= 262_144,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["method"] as? String == "turn/completed",
              let params = object["params"] as? [String: Any],
              params["threadId"] as? String == threadID,
              let turn = params["turn"] as? [String: Any],
              turn["id"] as? String == turnID,
              turn["status"] as? String == "completed" else {
            throw NativeAuthError.invalidToken("Codex completion authority")
        }
    }

    public static func verifyTrustedAccess(
        _ data: Data, threadID: String, turnID: String
    ) throws {
        guard data.count <= 65_536,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["method"] as? String == "model/verification",
              let params = object["params"] as? [String: Any],
              params["threadId"] as? String == threadID,
              params["turnId"] as? String == turnID,
              params["verifications"] as? [String] == ["trustedAccessForCyber"] else {
            throw NativeAuthError.invalidToken("Codex trusted-access verification")
        }
    }

    public static func rejectReroute(
        _ data: Data, threadID: String, turnID: String
    ) throws {
        guard data.count <= 65_536,
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw NativeAuthError.invalidToken("Codex notification")
        }
        guard object["method"] as? String == "model/rerouted" else { return }
        guard let params = object["params"] as? [String: Any],
              params["threadId"] as? String == threadID,
              params["turnId"] as? String == turnID else {
            throw NativeAuthError.invalidToken("Codex reroute identity")
        }
        throw NativeAuthError.invalidToken("Codex model rerouted")
    }
}

private func appServerVersionIsAdmitted(_ version: String) -> Bool {
    guard version.range(
        of: #"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?$"#,
        options: .regularExpression
    ) != nil else { return false }
    let numeric = version.split(separator: "-", maxSplits: 1)[0]
        .split(separator: ".").compactMap { Int($0) }
    guard numeric.count == 3 else { return false }
    return numeric.lexicographicallyPrecedes([0, 163, 0]) == false
}

private func exactObject(_ data: Data, maximum: Int) -> [String: Any]? {
    guard data.count <= maximum,
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          object["error"] == nil else { return nil }
    return object
}

func canonicalJSON(_ object: Any) throws -> Data {
    guard JSONSerialization.isValidJSONObject(object) else {
        throw NativeAuthError.invalidPolicy("JSON")
    }
    var data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    data.append(0x0a)
    return data
}

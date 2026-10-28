import Foundation
import Security

enum PPPCCommandLine {
    static let help = """
    PPPC Utility --cli <command> [options]

    help
    inspect --app PATH
    identities
    generate [--config JSON] [--app PATH --service Key=Authorization ...]
             --output PATH [--identifier ID] [--name NAME]
             [--organization TEXT] [--description TEXT] [--sign IDENTITY]
    modify --input PATH [--config JSON] [--app PATH --service Key=Authorization ...]
           --output PATH [--identifier ID] [--name NAME]
           [--organization TEXT] [--description TEXT] [--sign IDENTITY]
    sign --input PATH --output PATH --identity EXACT-NAME

    JSON is a configuration file path. Its schema is:
    {"metadata":{"identifier":"ID","name":"NAME","organization":"TEXT",
    "description":"TEXT"},"applications":[{"path":"/Applications/App.app",
    "services":{"Accessibility":"Allow"},"receiver":{"path":"/Applications/Receiver.app"}}]}
    Instead of path, an application or receiver may specify identifier and
    codeRequirement. Explicit absolute identifiers use IdentifierType path;
    other identifiers use bundleID. Remove may omit codeRequirement.
    Authorizations: Allow, Deny, AllowStandardUserToSetSystemService, Remove.
    Remove is only valid for modify. AppleEvents requires a receiver.
    --app is singular and must be accompanied by one or more --service flags;
    this application is appended to configuration applications.
    generate requires identifier, name, and at least one rule.
    Metadata flags override configuration metadata. Signing names must be unique.
    modify preserves unrelated profile data but replaces any existing signature.
    """

    private static let payloadType = "com.apple.TCC.configuration-profile-policy"

    private struct Failure: LocalizedError {
        let message: String
        var errorDescription: String? { message }
    }

    private struct Options {
        let command: String
        var values: [String: String] = [:]
        var services: [String: String] = [:]

        func required(_ flag: String) throws -> String {
            guard let value = values[flag] else {
                throw Failure(message: "\(command) requires \(flag).")
            }
            return value
        }
    }

    private struct Metadata: Decodable {
        var identifier: String?
        var name: String?
        var organization: String?
        var description: String?
    }

    private struct Target: Decodable {
        var path: String?
        var identifier: String?
        var codeRequirement: String?
    }

    private struct Application: Decodable {
        var path: String?
        var identifier: String?
        var codeRequirement: String?
        var services: [String: String]
        var receiver: Target?
    }

    private struct Configuration: Decodable {
        var metadata: Metadata?
        var applications: [Application]?
    }

    private struct ResolvedTarget {
        let identifier: String
        let type: String
        let requirement: String?
    }

    static func run(arguments: [String]) async throws -> String? {
        do {
            return try await execute(arguments: arguments)
        } catch let error as Failure {
            throw error
        } catch {
            throw Failure(message: "CLI operation failed: \(error.localizedDescription)")
        }
    }

    private static func execute(arguments: [String]) async throws -> String {
        let options = try parse(arguments)
        switch options.command {
        case "help":
            return help
        case "inspect":
            let executable = try Model().loadExecutable(url: fileURL(try options.required("--app")))
            guard let identifier = executable.identifier,
                  let requirement = executable.codeRequirement,
                  let displayName = executable.displayName else {
                throw Failure(message: "The executable has incomplete signing information.")
            }
            return try json(["identifier": identifier, "codeRequirement": requirement, "displayName": displayName])
        case "identities":
            return try json(try await SecurityWrapper.loadSigningIdentities().map(\.displayName).sorted())
        case "sign":
            let data = try Data(contentsOf: fileURL(try options.required("--input")))
            let output = try options.required("--output")
            let signed = try await sign(data, name: options.required("--identity"))
            try signed.write(to: fileURL(output), options: .atomic)
            return output
        default:
            return try await writeProfile(options)
        }
    }

    private static func parse(_ arguments: [String]) throws -> Options {
        guard let command = arguments.first else { return Options(command: "help") }
        if ["help", "--help", "-h"].contains(command) {
            guard arguments.count == 1 else { throw Failure(message: "Help does not accept options.") }
            return Options(command: "help")
        }
        let settings: Set<String> = ["--config", "--app", "--service", "--output", "--identifier", "--name", "--organization", "--description", "--sign"]
        let allowed: Set<String>
        switch command {
        case "inspect": allowed = ["--app"]
        case "identities": allowed = []
        case "generate": allowed = settings
        case "modify": allowed = settings.union(["--input"])
        case "sign": allowed = ["--input", "--output", "--identity"]
        default: throw Failure(message: "Unknown command '\(command)'. Use help for usage.")
        }
        if arguments.count == 2, ["--help", "-h"].contains(arguments[1]) {
            return Options(command: "help")
        }
        var result = Options(command: command)
        var index = 1
        while index < arguments.count {
            let flag = arguments[index]
            guard allowed.contains(flag) else {
                throw Failure(message: "Option '\(flag)' is not supported by \(command).")
            }
            guard index + 1 < arguments.count,
                  !arguments[index + 1].hasPrefix("--"),
                  !arguments[index + 1].trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
                throw Failure(message: "Missing value for \(flag).")
            }
            let value = arguments[index + 1]
            if flag == "--service" {
                let parts = value.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else {
                    throw Failure(message: "Invalid service '\(value)'; expected Key=Authorization.")
                }
                let key = String(parts[0])
                guard result.services[key] == nil else {
                    throw Failure(message: "Duplicate service '\(key)'.")
                }
                result.services[key] = String(parts[1])
            } else {
                guard result.values[flag] == nil else { throw Failure(message: "Duplicate option \(flag).") }
                result.values[flag] = value
            }
            index += 2
        }
        if command == "generate" || command == "modify" {
            guard (result.values["--app"] != nil) == !result.services.isEmpty else {
                throw Failure(message: "--app and --service must be supplied together.")
            }
        }
        return result
    }

    private static func writeProfile(_ options: Options) async throws -> String {
        let output = try options.required("--output")
        let modifying = options.command == "modify"
        var configuration = Configuration()
        if let path = options.values["--config"] {
            configuration = try JSONDecoder().decode(Configuration.self, from: Data(contentsOf: fileURL(path)))
        }
        var metadata = configuration.metadata ?? Metadata()
        metadata.identifier = options.values["--identifier"] ?? metadata.identifier
        metadata.name = options.values["--name"] ?? metadata.name
        metadata.organization = options.values["--organization"] ?? metadata.organization
        metadata.description = options.values["--description"] ?? metadata.description
        for (key, value) in [("identifier", metadata.identifier), ("name", metadata.name), ("organization", metadata.organization), ("description", metadata.description)] {
            if let value { try nonempty(value, field: "metadata.\(key)") }
        }
        var applications = configuration.applications ?? []
        if let path = options.values["--app"] {
            applications.append(Application(path: path, services: options.services))
        }
        var profile: [String: Any]
        var payloads: [[String: Any]]
        let payloadIndex: Int
        if modifying {
            profile = try readProfile(fileURL(try options.required("--input")))
            guard profile["PayloadType"] as? String == "Configuration",
                  let contents = profile["PayloadContent"] as? [[String: Any]] else {
                throw Failure(message: "Input must be a configuration profile with a PayloadContent array.")
            }
            let indices = contents.indices.filter { contents[$0]["PayloadType"] as? String == payloadType }
            guard indices.count == 1, let index = indices.first else {
                throw Failure(message: "Modification requires exactly one PPPC payload; found \(indices.count).")
            }
            payloads = contents
            payloadIndex = index
        } else {
            guard let identifier = metadata.identifier, let name = metadata.name else {
                throw Failure(message: "generate requires identifier and name in metadata or command options.")
            }
            profile = basePayload(type: "Configuration", identifier: identifier, name: name)
            profile["PayloadScope"] = "System"
            payloads = [basePayload(type: payloadType, identifier: identifier + ".pppc", name: name)]
            payloadIndex = 0
        }
        var payload = payloads[payloadIndex]
        var services: [String: [[String: Any]]] = [:]
        if let existing = payload["Services"] {
            guard let existing = existing as? [String: [[String: Any]]] else {
                throw Failure(message: "The PPPC payload contains an invalid Services dictionary.")
            }
            services = existing
        }
        let knownServices = PPPCServicesManager.shared.allServices
        guard !knownServices.isEmpty else { throw Failure(message: "Cannot load the PPPC services resource.") }
        var ruleCount = 0
        for application in applications {
            guard !application.services.isEmpty else { throw Failure(message: "Each application requires at least one service.") }
            let onlyRemoving = application.services.values.allSatisfy { $0 == "Remove" }
            let target = try resolve(Target(path: application.path, identifier: application.identifier, codeRequirement: application.codeRequirement), removing: modifying && onlyRemoving)
            let receiver = try application.receiver.map {
                try resolve($0, removing: modifying && application.services["AppleEvents"] == "Remove")
            }
            for key in application.services.keys.sorted() {
                guard let authorization = application.services[key], let info = knownServices[key] else {
                    throw Failure(message: "Unknown PPPC service '\(key)'.")
                }
                try validate(authorization, service: info, modifying: modifying)
                if key == "AppleEvents", receiver == nil {
                    throw Failure(message: "AppleEvents requires a receiver in the configuration file.")
                }
                let eventReceiver = key == "AppleEvents" ? receiver : nil
                var rules = services[key] ?? []
                let matchingIndices = rules.indices.filter { matches(rules[$0], target: target, receiver: eventReceiver) }
                if authorization == "Remove" {
                    for index in matchingIndices.reversed() { rules.remove(at: index) }
                } else {
                    var rule = matchingIndices.first.map { rules[$0] } ?? [:]
                    rule["Identifier"] = target.identifier
                    rule["IdentifierType"] = target.type
                    rule["CodeRequirement"] = target.requirement
                    rule.removeValue(forKey: "Allowed")
                    rule["Authorization"] = authorization
                    if let eventReceiver {
                        rule["AEReceiverIdentifier"] = eventReceiver.identifier
                        rule["AEReceiverIdentifierType"] = eventReceiver.type
                        rule["AEReceiverCodeRequirement"] = eventReceiver.requirement
                    }
                    if let first = matchingIndices.first {
                        rules[first] = rule
                        for index in matchingIndices.dropFirst().reversed() { rules.remove(at: index) }
                    } else {
                        rules.append(rule)
                    }
                    ruleCount += 1
                }
                services[key] = rules
            }
        }
        guard modifying || ruleCount > 0 else { throw Failure(message: "generate requires at least one actual rule.") }
        payload["Services"] = services
        payloads[payloadIndex] = payload
        profile["PayloadContent"] = payloads
        for (key, value) in [("PayloadIdentifier", metadata.identifier), ("PayloadDisplayName", metadata.name), ("PayloadOrganization", metadata.organization), ("PayloadDescription", metadata.description)] {
            if let value { profile[key] = value }
        }
        var data = try PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0)
        if let identity = options.values["--sign"] { data = try await sign(data, name: identity) }
        try data.write(to: fileURL(output), options: .atomic)
        return output
    }

    private static func resolve(_ target: Target, removing: Bool) throws -> ResolvedTarget {
        if let path = target.path {
            guard target.identifier == nil, target.codeRequirement == nil else {
                throw Failure(message: "Specify path OR identifier and codeRequirement, not both.")
            }
            try nonempty(path, field: "application path")
            let executable = try Model().loadExecutable(url: fileURL(path))
            guard let identifier = executable.identifier, let requirement = executable.codeRequirement else {
                throw Failure(message: "No identifier or code requirement found for '\(path)'.")
            }
            return ResolvedTarget(identifier: identifier, type: identifier.hasPrefix("/") ? "path" : "bundleID", requirement: requirement)
        }
        guard let identifier = target.identifier else {
            throw Failure(message: "An application or receiver requires path or identifier.")
        }
        try nonempty(identifier, field: "application identifier")
        if let requirement = target.codeRequirement {
            try nonempty(requirement, field: "codeRequirement")
            var parsed: SecRequirement?
            let status = SecRequirementCreateWithString(requirement as CFString, SecCSFlags(rawValue: 0), &parsed)
            guard status == errSecSuccess, parsed != nil else {
                throw Failure(message: "Invalid codeRequirement for '\(identifier)' (Security error \(status)).")
            }
        } else if !removing {
            throw Failure(message: "Explicit identifier '\(identifier)' requires codeRequirement.")
        }
        return ResolvedTarget(identifier: identifier, type: identifier.hasPrefix("/") ? "path" : "bundleID", requirement: target.codeRequirement)
    }

    private static func validate(_ authorization: String, service: PPPCServiceInfo, modifying: Bool) throws {
        switch authorization {
        case "Remove":
            guard modifying else { throw Failure(message: "Remove is only supported by modify.") }
        case "Deny": break
        case "Allow":
            guard service.denyOnly != true else { throw Failure(message: "\(service.mdmKey) does not support Allow.") }
        case "AllowStandardUserToSetSystemService":
            guard service.allowStandardUsers == true else {
                throw Failure(message: "\(service.mdmKey) does not support AllowStandardUserToSetSystemService.")
            }
        default: throw Failure(message: "Invalid authorization '\(authorization)' for \(service.mdmKey).")
        }
    }

    private static func matches(_ rule: [String: Any], target: ResolvedTarget, receiver: ResolvedTarget?) -> Bool {
        rule["Identifier"] as? String == target.identifier && rule["IdentifierType"] as? String == target.type &&
        rule["AEReceiverIdentifier"] as? String == receiver?.identifier && rule["AEReceiverIdentifierType"] as? String == receiver?.type
    }

    private static func readProfile(_ url: URL) throws -> [String: Any] {
        let original = try Data(contentsOf: url)
        var data = original
        if let decoder = SwiftyCMSDecoder() {
            decoder.updateMessage(data: original as NSData)
            decoder.finaliseMessage()
            if let decoded = decoder.data { data = decoded }
        }
        guard let profile = try PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            throw Failure(message: "Input profile is not a property-list dictionary.")
        }
        return profile
    }

    private static func basePayload(type: String, identifier: String, name: String) -> [String: Any] {
        ["PayloadType": type, "PayloadVersion": 1, "PayloadUUID": UUID().uuidString,
         "PayloadIdentifier": identifier, "PayloadDisplayName": name]
    }

    private static func sign(_ data: Data, name: String) async throws -> Data {
        let identities = try await SecurityWrapper.loadSigningIdentities().filter { $0.displayName == name }
        guard identities.count == 1, let identity = identities.first, let reference = identity.reference else {
            throw Failure(message: identities.isEmpty ? "No signing identity exactly matches '\(name)'." : "Signing identity '\(name)' is ambiguous or unavailable.")
        }
        return try await SecurityWrapper.sign(data: data, using: reference)
    }

    private static func fileURL(_ path: String) -> URL {
        URL(fileURLWithPath: (path as NSString).expandingTildeInPath)
    }

    private static func nonempty(_ value: String, field: String) throws {
        guard !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw Failure(message: "\(field) must not be empty.")
        }
    }

    private static func json(_ value: Any) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys])
        guard let string = String(data: data, encoding: .utf8) else {
            throw Failure(message: "Could not encode JSON output.")
        }
        return string
    }
}

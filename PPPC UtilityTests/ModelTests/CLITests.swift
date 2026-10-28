import Foundation
import Testing

@testable import PPPC_Utility

@Suite
final class CLITests {
    private let directory: URL
    private let requirement = "identifier \"com.example.app\""

    init() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    deinit {
        try? FileManager.default.removeItem(at: directory)
    }

    @Test("Generate uses an explicit requirement from configuration and metadata flags override configuration")
    func generateExplicitRequirement() async throws {
        let config = try writeConfiguration(services: ["Accessibility": "Allow"])
        let output = directory.appendingPathComponent("generated.mobileconfig")
        let result = try await PPPCCommandLine.run(arguments: [
            "generate", "--config", config.path, "--output", output.path,
            "--identifier", "com.example.override", "--name", "Override Name",
            "--organization", "Override Organization", "--description", "Override Description"
        ])
        let profile = try readProfile(output)
        let payloads = try #require(profile["PayloadContent"] as? [[String: Any]])
        let payload = try #require(payloads.first)
        let services = try #require(payload["Services"] as? [String: [[String: Any]]])
        let rules = try #require(services["Accessibility"])
        let rule = try #require(rules.first)

        #expect(result == output.path)
        #expect(profile["PayloadType"] as? String == "Configuration")
        #expect(profile["PayloadScope"] as? String == "System")
        #expect(profile["PayloadIdentifier"] as? String == "com.example.override")
        #expect(profile["PayloadDisplayName"] as? String == "Override Name")
        #expect(profile["PayloadOrganization"] as? String == "Override Organization")
        #expect(profile["PayloadDescription"] as? String == "Override Description")
        #expect(payloads.count == 1)
        #expect(rules.count == 1)
        #expect(rule["Identifier"] as? String == "com.example.app")
        #expect(rule["IdentifierType"] as? String == "bundleID")
        #expect(rule["CodeRequirement"] as? String == requirement)
        #expect(rule["Authorization"] as? String == "Allow")
        #expect(rule["Allowed"] == nil)
        let profileUUID = try #require(profile["PayloadUUID"] as? String)
        let payloadUUID = try #require(payload["PayloadUUID"] as? String)
        #expect(UUID(uuidString: profileUUID) != nil)
        #expect(UUID(uuidString: payloadUUID) != nil)
        #expect(profileUUID != payloadUUID)
    }

    @Test("Modify preserves unrelated profile data and UUIDs while upserting and removing legacy Allowed")
    func modifyPreservesProfileAndUpsertsRule() async throws {
        let original = makeProfile()
        let input = try writeProfile(original)
        let config = try writeConfiguration(services: ["Accessibility": "Deny"])
        let output = directory.appendingPathComponent("modified.mobileconfig")
        let result = try await PPPCCommandLine.run(arguments: [
            "modify", "--input", input.path, "--config", config.path, "--output", output.path
        ])
        let profile = try readProfile(output)
        let originalPayloads = try #require(original["PayloadContent"] as? [[String: Any]])
        let payloads = try #require(profile["PayloadContent"] as? [[String: Any]])
        let payload = try #require(payloads.last)
        let services = try #require(payload["Services"] as? [String: [[String: Any]]])
        let rules = try #require(services["Accessibility"])
        let rule = try #require(rules.first)
        let originalServices = try #require(originalPayloads.last?["Services"] as? [String: [[String: Any]]])
        let originalRules = try #require(originalServices["Accessibility"])

        #expect(result == output.path)
        #expect(profile["PayloadUUID"] as? String == original["PayloadUUID"] as? String)
        #expect(profile["CustomProfileKey"] as? [String: String] == ["keep": "profile"])
        #expect(payloads.count == originalPayloads.count)
        #expect(NSDictionary(dictionary: try #require(payloads.first)).isEqual(to: try #require(originalPayloads.first)))
        #expect(payload["PayloadUUID"] as? String == originalPayloads.last?["PayloadUUID"] as? String)
        #expect(payload["CustomPayloadKey"] as? [String] == ["keep", "payload"])
        #expect(NSDictionary(dictionary: services).allKeys.count == originalServices.count)
        #expect(services["FutureService"]?.count == 1)
        #expect(NSDictionary(dictionary: try #require(services["FutureService"]?.first))
            .isEqual(to: try #require(originalServices["FutureService"]?.first)))
        #expect(rules.count == 2)
        #expect(rule["Authorization"] as? String == "Deny")
        #expect(rule["Allowed"] == nil)
        #expect(rule["CodeRequirement"] as? String == requirement)
        #expect(rule["CustomRuleKey"] as? String == "keep rule")
        #expect(NSDictionary(dictionary: try #require(rules.last)).isEqual(to: try #require(originalRules.last)))
        #expect(NSDictionary(dictionary: try readProfile(input)).isEqual(to: original))
    }

    @Test("Remove needs no requirement and removes every matching rule without touching other applications")
    func removeWithoutRequirement() async throws {
        let input = try writeProfile(makeProfile())
        let config = try writeConfiguration(services: ["Accessibility": "Remove"], includeRequirement: false)
        let output = directory.appendingPathComponent("removed.mobileconfig")
        _ = try await PPPCCommandLine.run(arguments: [
            "modify", "--input", input.path, "--config", config.path, "--output", output.path
        ])
        let profile = try readProfile(output)
        let payloads = try #require(profile["PayloadContent"] as? [[String: Any]])
        let services = try #require(payloads.last?["Services"] as? [String: [[String: Any]]])
        let rules = try #require(services["Accessibility"])

        #expect(rules.count == 1)
        #expect(rules.first?["Identifier"] as? String == "com.example.other")
        #expect(rules.first?["Allowed"] as? Bool == true)
        #expect(services["FutureService"]?.count == 1)
    }

    @Test("Configuration rules reject unsupported services and authorizations", arguments: [
        ("Camera", "Allow"),
        ("ScreenCapture", "Allow"),
        ("Accessibility", "AllowStandardUserToSetSystemService"),
        ("Camera", "AllowStandardUserToSetSystemService"),
        ("UnknownService", "Allow"),
        ("Accessibility", "UnknownAuthorization"),
        ("Accessibility", "Remove")
    ])
    func rejectsInvalidRule(service: String, authorization: String) async throws {
        let config = try writeConfiguration(services: [service: authorization])
        let message: String
        if service == "UnknownService" {
            message = "Unknown PPPC service '\(service)'."
        } else if authorization == "Remove" {
            message = "Remove is only supported by modify."
        } else if authorization == "UnknownAuthorization" {
            message = "Invalid authorization '\(authorization)' for \(service)."
        } else {
            message = "\(service) does not support \(authorization)."
        }
        await expectFailure(["generate", "--config", config.path], message: message)
    }

    @Test("Argument validation rejects unknown flags, duplicates, missing values, and unpaired application flags", arguments: [
        (["--unknown", "value"], "Option '--unknown' is not supported by generate."),
        (["--input", "profile"], "Option '--input' is not supported by generate."),
        (["--name", "First", "--name", "Second"], "Duplicate option --name."),
        (["--service", "Accessibility=Allow", "--service", "Accessibility=Deny"], "Duplicate service 'Accessibility'."),
        (["--name"], "Missing value for --name."),
        (["--name", "--identifier", "com.example.profile"], "Missing value for --name."),
        (["--name", "  "], "Missing value for --name."),
        (["--service", "Accessibility"], "Invalid service 'Accessibility'; expected Key=Authorization."),
        (["--service", "=Allow"], "Invalid service '=Allow'; expected Key=Authorization."),
        (["--service", "Accessibility="], "Invalid service 'Accessibility='; expected Key=Authorization."),
        (["--app", "/nonexistent/App.app"], "--app and --service must be supplied together."),
        (["--service", "Accessibility=Allow"], "--app and --service must be supplied together.")
    ])
    func rejectsInvalidArguments(flags: [String], message: String) async {
        await expectFailure(["generate"] + flags, message: message)
    }

    @Test("Configuration does not replace the requirement to pair app and service flags", arguments: [
        ["--app", "/nonexistent/App.app"],
        ["--service", "Accessibility=Allow"]
    ])
    func rejectsUnpairedFlagsWithConfiguration(flags: [String]) async throws {
        let config = try writeConfiguration(services: ["Accessibility": "Allow"])
        await expectFailure(
            ["generate", "--config", config.path] + flags,
            message: "--app and --service must be supplied together."
        )
    }

    @Test("Explicit identifiers require a code requirement when generating rules")
    func rejectsMissingRequirement() async throws {
        let config = try writeConfiguration(services: ["Accessibility": "Allow"], includeRequirement: false)
        await expectFailure(
            ["generate", "--config", config.path],
            message: "Explicit identifier 'com.example.app' requires codeRequirement."
        )
    }

    private func expectFailure(_ arguments: [String], message: String) async {
        let output = directory.appendingPathComponent(UUID().uuidString + ".mobileconfig")
        do {
            _ = try await PPPCCommandLine.run(arguments: arguments + ["--output", output.path])
            Issue.record("Expected CLI rejection: \(message)")
        } catch {
            #expect(error.localizedDescription == message)
        }
        #expect(!FileManager.default.fileExists(atPath: output.path))
    }

    private func writeConfiguration(services: [String: String], includeRequirement: Bool = true) throws -> URL {
        var application: [String: Any] = ["identifier": "com.example.app", "services": services]
        if includeRequirement {
            application["codeRequirement"] = requirement
        }
        let configuration: [String: Any] = [
            "metadata": [
                "identifier": "com.example.profile", "name": "Example Profile",
                "organization": "Example Organization", "description": "Example Description"
            ],
            "applications": [application]
        ]
        let url = directory.appendingPathComponent(UUID().uuidString + ".json")
        try JSONSerialization.data(withJSONObject: configuration).write(to: url)
        return url
    }

    private func makeProfile() -> [String: Any] {
        let rule: [String: Any] = [
            "Identifier": "com.example.app", "IdentifierType": "bundleID",
            "CodeRequirement": requirement, "Allowed": true, "CustomRuleKey": "keep rule"
        ]
        let otherRule: [String: Any] = [
            "Identifier": "com.example.other", "IdentifierType": "bundleID", "Allowed": true
        ]
        return [
            "PayloadType": "Configuration", "PayloadVersion": 1,
            "PayloadIdentifier": "com.example.profile", "PayloadDisplayName": "Original Profile",
            "PayloadUUID": UUID().uuidString, "CustomProfileKey": ["keep": "profile"],
            "PayloadContent": [
                [
                    "PayloadType": "com.example.unrelated", "PayloadVersion": 1,
                    "PayloadUUID": UUID().uuidString, "CustomData": ["untouched": true]
                ],
                [
                    "PayloadType": "com.apple.TCC.configuration-profile-policy", "PayloadVersion": 1,
                    "PayloadUUID": UUID().uuidString, "PayloadIdentifier": "com.example.profile.pppc",
                    "CustomPayloadKey": ["keep", "payload"],
                    "Services": [
                        "Accessibility": [rule, rule, otherRule],
                        "FutureService": [["Identifier": "com.example.future", "CustomValue": 42]]
                    ]
                ]
            ]
        ]
    }

    private func writeProfile(_ profile: [String: Any]) throws -> URL {
        let url = directory.appendingPathComponent(UUID().uuidString + ".mobileconfig")
        try PropertyListSerialization.data(fromPropertyList: profile, format: .xml, options: 0).write(to: url)
        return url
    }

    private func readProfile(_ url: URL) throws -> [String: Any] {
        let data = try Data(contentsOf: url)
        return try #require(PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any])
    }
}

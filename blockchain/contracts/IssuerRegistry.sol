// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title IssuerRegistry
 * @notice Research prototype registry for authorised academic credential issuers.
 *
 * The contract links:
 * - a UKPRN
 * - a research issuer DID
 * - an authorised verification method
 * - active/inactive status
 *
 * It does NOT store student personal data or academic credentials.
 */
contract IssuerRegistry {

    address public owner;

    struct Issuer {
        uint256 ukprn;
        string issuerDid;
        string verificationMethod;
        bool active;
        uint256 registeredAt;
        uint256 updatedAt;
    }

    mapping(uint256 => Issuer) private issuers;

    event IssuerRegistered(
        uint256 indexed ukprn,
        string issuerDid,
        string verificationMethod,
        uint256 timestamp
    );

    event IssuerDeactivated(
        uint256 indexed ukprn,
        uint256 timestamp
    );

    event IssuerReactivated(
        uint256 indexed ukprn,
        uint256 timestamp
    );

    event VerificationMethodUpdated(
        uint256 indexed ukprn,
        string verificationMethod,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(
            msg.sender == owner,
            "Only registry owner"
        );
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function registerIssuer(
        uint256 ukprn,
        string calldata issuerDid,
        string calldata verificationMethod
    )
        external
        onlyOwner
    {
        require(
            ukprn > 0,
            "Invalid UKPRN"
        );

        require(
            bytes(issuerDid).length > 0,
            "Issuer DID required"
        );

        require(
            bytes(verificationMethod).length > 0,
            "Verification method required"
        );

        require(
            issuers[ukprn].registeredAt == 0,
            "Issuer already registered"
        );

        issuers[ukprn] = Issuer({
            ukprn: ukprn,
            issuerDid: issuerDid,
            verificationMethod: verificationMethod,
            active: true,
            registeredAt: block.timestamp,
            updatedAt: block.timestamp
        });

        emit IssuerRegistered(
            ukprn,
            issuerDid,
            verificationMethod,
            block.timestamp
        );
    }

    function deactivateIssuer(
        uint256 ukprn
    )
        external
        onlyOwner
    {
        Issuer storage issuer = issuers[ukprn];

        require(
            issuer.registeredAt != 0,
            "Issuer not registered"
        );

        require(
            issuer.active,
            "Issuer already inactive"
        );

        issuer.active = false;
        issuer.updatedAt = block.timestamp;

        emit IssuerDeactivated(
            ukprn,
            block.timestamp
        );
    }

    function reactivateIssuer(
        uint256 ukprn
    )
        external
        onlyOwner
    {
        Issuer storage issuer = issuers[ukprn];

        require(
            issuer.registeredAt != 0,
            "Issuer not registered"
        );

        require(
            !issuer.active,
            "Issuer already active"
        );

        issuer.active = true;
        issuer.updatedAt = block.timestamp;

        emit IssuerReactivated(
            ukprn,
            block.timestamp
        );
    }

    function updateVerificationMethod(
        uint256 ukprn,
        string calldata newVerificationMethod
    )
        external
        onlyOwner
    {
        Issuer storage issuer = issuers[ukprn];

        require(
            issuer.registeredAt != 0,
            "Issuer not registered"
        );

        require(
            bytes(newVerificationMethod).length > 0,
            "Verification method required"
        );

        issuer.verificationMethod =
            newVerificationMethod;

        issuer.updatedAt =
            block.timestamp;

        emit VerificationMethodUpdated(
            ukprn,
            newVerificationMethod,
            block.timestamp
        );
    }

    function getIssuer(
        uint256 ukprn
    )
        external
        view
        returns (
            uint256,
            string memory,
            string memory,
            bool,
            uint256,
            uint256
        )
    {
        Issuer memory issuer =
            issuers[ukprn];

        require(
            issuer.registeredAt != 0,
            "Issuer not registered"
        );

        return (
            issuer.ukprn,
            issuer.issuerDid,
            issuer.verificationMethod,
            issuer.active,
            issuer.registeredAt,
            issuer.updatedAt
        );
    }

    function isIssuerAuthorized(
        uint256 ukprn,
        string calldata issuerDid,
        string calldata verificationMethod
    )
        external
        view
        returns (bool)
    {
        Issuer memory issuer =
            issuers[ukprn];

        if (
            issuer.registeredAt == 0
            || !issuer.active
        ) {
            return false;
        }

        bool didMatches =
            keccak256(
                bytes(issuer.issuerDid)
            )
            ==
            keccak256(
                bytes(issuerDid)
            );

        bool keyMatches =
            keccak256(
                bytes(
                    issuer.verificationMethod
                )
            )
            ==
            keccak256(
                bytes(
                    verificationMethod
                )
            );

        return (
            didMatches
            && keyMatches
        );
    }
}
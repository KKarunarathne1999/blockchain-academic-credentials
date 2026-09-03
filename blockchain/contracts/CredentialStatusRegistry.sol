// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title CredentialStatusRegistry
 * @notice Research prototype for credential-level
 *         revocation management.
 *
 * The contract stores only a hash-derived credential
 * identifier and revocation metadata.
 *
 * It does NOT store:
 * - student names
 * - programme details
 * - grades
 * - full credential documents
 * - other personal credential data
 */
contract CredentialStatusRegistry {

    address public owner;

    struct CredentialStatus {
        bool registered;
        bool revoked;
        uint256 registeredAt;
        uint256 revokedAt;
    }

    mapping(bytes32 => CredentialStatus)
        private credentialStatuses;

    event CredentialRegistered(
        bytes32 indexed credentialHash,
        uint256 timestamp
    );

    event CredentialRevoked(
        bytes32 indexed credentialHash,
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

    function registerCredential(
        bytes32 credentialHash
    )
        external
        onlyOwner
    {
        require(
            credentialHash != bytes32(0),
            "Invalid credential hash"
        );

        require(
            !credentialStatuses[
                credentialHash
            ].registered,
            "Credential already registered"
        );

        credentialStatuses[
            credentialHash
        ] = CredentialStatus({
            registered: true,
            revoked: false,
            registeredAt: block.timestamp,
            revokedAt: 0
        });

        emit CredentialRegistered(
            credentialHash,
            block.timestamp
        );
    }

    function revokeCredential(
        bytes32 credentialHash
    )
        external
        onlyOwner
    {
        CredentialStatus storage status =
            credentialStatuses[
                credentialHash
            ];

        require(
            status.registered,
            "Credential not registered"
        );

        require(
            !status.revoked,
            "Credential already revoked"
        );

        status.revoked = true;
        status.revokedAt =
            block.timestamp;

        emit CredentialRevoked(
            credentialHash,
            block.timestamp
        );
    }

    function isCredentialRegistered(
        bytes32 credentialHash
    )
        external
        view
        returns (bool)
    {
        return credentialStatuses[
            credentialHash
        ].registered;
    }

    function isCredentialRevoked(
        bytes32 credentialHash
    )
        external
        view
        returns (bool)
    {
        CredentialStatus memory status =
            credentialStatuses[
                credentialHash
            ];

        if (!status.registered) {
            return false;
        }

        return status.revoked;
    }

    function isCredentialValid(
        bytes32 credentialHash
    )
        external
        view
        returns (bool)
    {
        CredentialStatus memory status =
            credentialStatuses[
                credentialHash
            ];

        return (
            status.registered
            && !status.revoked
        );
    }

    function getCredentialStatus(
        bytes32 credentialHash
    )
        external
        view
        returns (
            bool,
            bool,
            uint256,
            uint256
        )
    {
        CredentialStatus memory status =
            credentialStatuses[
                credentialHash
            ];

        require(
            status.registered,
            "Credential not registered"
        );

        return (
            status.registered,
            status.revoked,
            status.registeredAt,
            status.revokedAt
        );
    }
}
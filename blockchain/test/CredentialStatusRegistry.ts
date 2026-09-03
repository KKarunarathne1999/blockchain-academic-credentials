import { expect } from "chai";
import { network } from "hardhat";

describe(
  "CredentialStatusRegistry",
  function () {

    async function deployRegistry() {

      const { ethers } =
        await network.getOrCreate();

      const [
        owner,
        otherAccount,
      ] =
        await ethers.getSigners();

      const Registry =
        await ethers.getContractFactory(
          "CredentialStatusRegistry"
        );

      const registry =
        await Registry.deploy();

      await registry.waitForDeployment();

      return {
        ethers,
        registry,
        owner,
        otherAccount,
      };
    }


    function createCredentialHash(
      ethers: any,
      credentialId:
        string = "CRED-000000000001"
    ) {

      return ethers.keccak256(
        ethers.toUtf8Bytes(
          credentialId
        )
      );
    }


    it(
      "sets the deployer as owner",
      async function () {

        const {
          registry,
          owner,
        } =
          await deployRegistry();

        expect(
          await registry.owner()
        ).to.equal(
          owner.address
        );
      }
    );


    it(
      "allows the owner to register a credential",
      async function () {

        const {
          ethers,
          registry,
        } =
          await deployRegistry();

        const credentialHash =
          createCredentialHash(
            ethers
          );

        await registry
          .registerCredential(
            credentialHash
          );

        expect(
          await registry
            .isCredentialRegistered(
              credentialHash
            )
        ).to.equal(
          true
        );

        expect(
          await registry
            .isCredentialRevoked(
              credentialHash
            )
        ).to.equal(
          false
        );

        expect(
          await registry
            .isCredentialValid(
              credentialHash
            )
        ).to.equal(
          true
        );
      }
    );


    it(
      "rejects duplicate credential registration",
      async function () {

        const {
          ethers,
          registry,
        } =
          await deployRegistry();

        const credentialHash =
          createCredentialHash(
            ethers
          );

        await registry
          .registerCredential(
            credentialHash
          );

        await expect(
          registry
            .registerCredential(
              credentialHash
            )
        ).to.be.revertedWith(
          "Credential already registered"
        );
      }
    );


    it(
      "rejects registration from a non-owner",
      async function () {

        const {
          ethers,
          registry,
          otherAccount,
        } =
          await deployRegistry();

        const credentialHash =
          createCredentialHash(
            ethers
          );

        await expect(
          registry
            .connect(
              otherAccount
            )
            .registerCredential(
              credentialHash
            )
        ).to.be.revertedWith(
          "Only registry owner"
        );
      }
    );


    it(
      "allows the owner to revoke a credential",
      async function () {

        const {
          ethers,
          registry,
        } =
          await deployRegistry();

        const credentialHash =
          createCredentialHash(
            ethers
          );

        await registry
          .registerCredential(
            credentialHash
          );

        await registry
          .revokeCredential(
            credentialHash
          );

        expect(
          await registry
            .isCredentialRevoked(
              credentialHash
            )
        ).to.equal(
          true
        );

        expect(
          await registry
            .isCredentialValid(
              credentialHash
            )
        ).to.equal(
          false
        );
      }
    );


    it(
      "rejects duplicate revocation",
      async function () {

        const {
          ethers,
          registry,
        } =
          await deployRegistry();

        const credentialHash =
          createCredentialHash(
            ethers
          );

        await registry
          .registerCredential(
            credentialHash
          );

        await registry
          .revokeCredential(
            credentialHash
          );

        await expect(
          registry
            .revokeCredential(
              credentialHash
            )
        ).to.be.revertedWith(
          "Credential already revoked"
        );
      }
    );


    it(
      "rejects revocation of an unknown credential",
      async function () {

        const {
          ethers,
          registry,
        } =
          await deployRegistry();

        const credentialHash =
          createCredentialHash(
            ethers,
            "UNKNOWN-CREDENTIAL"
          );

        await expect(
          registry
            .revokeCredential(
              credentialHash
            )
        ).to.be.revertedWith(
          "Credential not registered"
        );
      }
    );


    it(
      "rejects revocation from a non-owner",
      async function () {

        const {
          ethers,
          registry,
          otherAccount,
        } =
          await deployRegistry();

        const credentialHash =
          createCredentialHash(
            ethers
          );

        await registry
          .registerCredential(
            credentialHash
          );

        await expect(
          registry
            .connect(
              otherAccount
            )
            .revokeCredential(
              credentialHash
            )
        ).to.be.revertedWith(
          "Only registry owner"
        );
      }
    );


    it(
      "returns false status for an unknown credential",
      async function () {

        const {
          ethers,
          registry,
        } =
          await deployRegistry();

        const credentialHash =
          createCredentialHash(
            ethers,
            "UNKNOWN-CREDENTIAL"
          );

        expect(
          await registry
            .isCredentialRegistered(
              credentialHash
            )
        ).to.equal(
          false
        );

        expect(
          await registry
            .isCredentialRevoked(
              credentialHash
            )
        ).to.equal(
          false
        );

        expect(
          await registry
            .isCredentialValid(
              credentialHash
            )
        ).to.equal(
          false
        );
      }
    );


    it(
      "rejects the zero credential hash",
      async function () {

        const {
          ethers,
          registry,
        } =
          await deployRegistry();

        const zeroHash =
          ethers.ZeroHash;

        await expect(
          registry
            .registerCredential(
              zeroHash
            )
        ).to.be.revertedWith(
          "Invalid credential hash"
        );
      }
    );


    it(
      "returns credential status metadata",
      async function () {

        const {
          ethers,
          registry,
        } =
          await deployRegistry();

        const credentialHash =
          createCredentialHash(
            ethers
          );

        await registry
          .registerCredential(
            credentialHash
          );

        const beforeRevocation =
          await registry
            .getCredentialStatus(
              credentialHash
            );

        expect(
          beforeRevocation[0]
        ).to.equal(
          true
        );

        expect(
          beforeRevocation[1]
        ).to.equal(
          false
        );

        expect(
          beforeRevocation[2]
        ).to.be.greaterThan(
          0
        );

        expect(
          beforeRevocation[3]
        ).to.equal(
          0
        );

        await registry
          .revokeCredential(
            credentialHash
          );

        const afterRevocation =
          await registry
            .getCredentialStatus(
              credentialHash
            );

        expect(
          afterRevocation[0]
        ).to.equal(
          true
        );

        expect(
          afterRevocation[1]
        ).to.equal(
          true
        );

        expect(
          afterRevocation[3]
        ).to.be.greaterThan(
          0
        );
      }
    );


    it(
      "rejects status metadata lookup for unknown credential",
      async function () {

        const {
          ethers,
          registry,
        } =
          await deployRegistry();

        const credentialHash =
          createCredentialHash(
            ethers,
            "UNKNOWN-CREDENTIAL"
          );

        await expect(
          registry
            .getCredentialStatus(
              credentialHash
            )
        ).to.be.revertedWith(
          "Credential not registered"
        );
      }
    );

  }
);
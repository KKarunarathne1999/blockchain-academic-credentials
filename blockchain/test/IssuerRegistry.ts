import { expect } from "chai";
import { network } from "hardhat";

describe("IssuerRegistry", function () {
  async function deployRegistry() {
    const { ethers } = await network.getOrCreate();

    const [owner, other] =
      await ethers.getSigners();

    const registry =
      await ethers.deployContract(
        "IssuerRegistry"
      );

    await registry.waitForDeployment();

    return {
      ethers,
      registry,
      owner,
      other,
    };
  }

  const ukprn = 10005553n;

  const issuerDid =
    "did:example:issuer:ukprn-10005553";

  const verificationMethod =
    "did:key:z6MkiiExample#z6MkiiExample";

  it(
    "sets the deployer as owner",
    async function () {
      const {
        registry,
        owner,
      } = await deployRegistry();

      expect(
        await registry.owner()
      ).to.equal(
        owner.address
      );
    }
  );

  it(
    "allows the owner to register an issuer",
    async function () {
      const {
        registry,
      } = await deployRegistry();

      const transaction =
        await registry.registerIssuer(
          ukprn,
          issuerDid,
          verificationMethod
        );

      await transaction.wait();

      const issuer =
        await registry.getIssuer(
          ukprn
        );

      expect(
        issuer[0]
      ).to.equal(
        ukprn
      );

      expect(
        issuer[1]
      ).to.equal(
        issuerDid
      );

      expect(
        issuer[2]
      ).to.equal(
        verificationMethod
      );

      expect(
        issuer[3]
      ).to.equal(
        true
      );
    }
  );

  it(
    "rejects duplicate issuer registration",
    async function () {
      const {
        ethers,
        registry,
      } = await deployRegistry();

      await (
        await registry.registerIssuer(
          ukprn,
          issuerDid,
          verificationMethod
        )
      ).wait();

      await expect(
        registry.registerIssuer(
          ukprn,
          issuerDid,
          verificationMethod
        )
      ).to.be.revertedWith(
        "Issuer already registered"
      );
    }
  );

  it(
    "rejects registration from a non-owner",
    async function () {
      const {
        registry,
        other,
      } = await deployRegistry();

      await expect(
        registry
          .connect(other)
          .registerIssuer(
            ukprn,
            issuerDid,
            verificationMethod
          )
      ).to.be.revertedWith(
        "Only registry owner"
      );
    }
  );

  it(
    "returns true for an authorised issuer",
    async function () {
      const {
        registry,
      } = await deployRegistry();

      await (
        await registry.registerIssuer(
          ukprn,
          issuerDid,
          verificationMethod
        )
      ).wait();

      expect(
        await registry.isIssuerAuthorized(
          ukprn,
          issuerDid,
          verificationMethod
        )
      ).to.equal(
        true
      );
    }
  );

  it(
    "returns false for wrong issuer DID",
    async function () {
      const {
        registry,
      } = await deployRegistry();

      await (
        await registry.registerIssuer(
          ukprn,
          issuerDid,
          verificationMethod
        )
      ).wait();

      expect(
        await registry.isIssuerAuthorized(
          ukprn,
          "did:example:issuer:fake",
          verificationMethod
        )
      ).to.equal(
        false
      );
    }
  );

  it(
    "returns false for wrong verification method",
    async function () {
      const {
        registry,
      } = await deployRegistry();

      await (
        await registry.registerIssuer(
          ukprn,
          issuerDid,
          verificationMethod
        )
      ).wait();

      expect(
        await registry.isIssuerAuthorized(
          ukprn,
          issuerDid,
          "did:key:zFake#zFake"
        )
      ).to.equal(
        false
      );
    }
  );

  it(
    "allows owner to deactivate an issuer",
    async function () {
      const {
        registry,
      } = await deployRegistry();

      await (
        await registry.registerIssuer(
          ukprn,
          issuerDid,
          verificationMethod
        )
      ).wait();

      await (
        await registry.deactivateIssuer(
          ukprn
        )
      ).wait();

      expect(
        await registry.isIssuerAuthorized(
          ukprn,
          issuerDid,
          verificationMethod
        )
      ).to.equal(
        false
      );
    }
  );

  it(
    "allows owner to reactivate an issuer",
    async function () {
      const {
        registry,
      } = await deployRegistry();

      await (
        await registry.registerIssuer(
          ukprn,
          issuerDid,
          verificationMethod
        )
      ).wait();

      await (
        await registry.deactivateIssuer(
          ukprn
        )
      ).wait();

      await (
        await registry.reactivateIssuer(
          ukprn
        )
      ).wait();

      expect(
        await registry.isIssuerAuthorized(
          ukprn,
          issuerDid,
          verificationMethod
        )
      ).to.equal(
        true
      );
    }
  );

  it(
    "updates the verification method",
    async function () {
      const {
        registry,
      } = await deployRegistry();

      await (
        await registry.registerIssuer(
          ukprn,
          issuerDid,
          verificationMethod
        )
      ).wait();

      const newMethod =
        "did:key:z6MkiiUpdated#z6MkiiUpdated";

      await (
        await registry.updateVerificationMethod(
          ukprn,
          newMethod
        )
      ).wait();

      expect(
        await registry.isIssuerAuthorized(
          ukprn,
          issuerDid,
          verificationMethod
        )
      ).to.equal(
        false
      );

      expect(
        await registry.isIssuerAuthorized(
          ukprn,
          issuerDid,
          newMethod
        )
      ).to.equal(
        true
      );
    }
  );

  it(
    "rejects administrative actions from non-owner accounts",
    async function () {
      const {
        registry,
        other,
      } = await deployRegistry();

      await (
        await registry.registerIssuer(
          ukprn,
          issuerDid,
          verificationMethod
        )
      ).wait();

      await expect(
        registry
          .connect(other)
          .deactivateIssuer(
            ukprn
          )
      ).to.be.revertedWith(
        "Only registry owner"
      );

      await expect(
        registry
          .connect(other)
          .updateVerificationMethod(
            ukprn,
            "did:key:zAttack#zAttack"
          )
      ).to.be.revertedWith(
        "Only registry owner"
      );
    }
  );
});
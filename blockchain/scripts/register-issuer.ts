import { network } from "hardhat";

async function main() {
  const { ethers } =
    await network.getOrCreate();

  const registryAddress =
    "0x5FbDB2315678afecb367f032d93F642f64180aa3";

  const ukprn =
    10005553n;

  const issuerDid =
    "did:example:issuer:ukprn-10005553";

  const verificationMethod =
    "did:key:z6MkiiZELAGKMmDh6xpogFEMacqfvB8F7o5XU1Pq7hFvXfgU#z6MkiiZELAGKMmDh6xpogFEMacqfvB8F7o5XU1Pq7hFvXfgU";

  const registry =
    await ethers.getContractAt(
      "IssuerRegistry",
      registryAddress
    );

  console.log(
    "Registering issuer..."
  );

  console.log(
    "Registry:",
    registryAddress
  );

  console.log(
    "UKPRN:",
    ukprn.toString()
  );

  console.log(
    "Issuer DID:",
    issuerDid
  );

  console.log(
    "Verification method:",
    verificationMethod
  );

  const transaction =
    await registry.registerIssuer(
      ukprn,
      issuerDid,
      verificationMethod
    );

  const receipt =
    await transaction.wait();

  console.log(
    "Transaction hash:",
    receipt?.hash
  );

  const issuer =
    await registry.getIssuer(
      ukprn
    );

  console.log("\nON-CHAIN ISSUER RECORD");

  console.log(
    "UKPRN:",
    issuer[0].toString()
  );

  console.log(
    "Issuer DID:",
    issuer[1]
  );

  console.log(
    "Verification method:",
    issuer[2]
  );

  console.log(
    "Active:",
    issuer[3]
  );

  console.log(
    "Registered at:",
    issuer[4].toString()
  );

  console.log(
    "Updated at:",
    issuer[5].toString()
  );

  const authorised =
    await registry.isIssuerAuthorized(
      ukprn,
      issuerDid,
      verificationMethod
    );

  console.log(
    "\nAuthorization check:",
    authorised
      ? "AUTHORIZED"
      : "NOT AUTHORIZED"
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
import { network } from "hardhat";

const STATUS_REGISTRY_ADDRESS =
  "0x0165878A594ca255338adfa4d48449f69242Eb8F";

const CREDENTIAL_ID =
  "urn:academic-credential:cred-000000000001";


async function main() {

  const { ethers } =
    await network.getOrCreate();

  const [account] =
    await ethers.getSigners();

  const Registry =
    await ethers.getContractFactory(
      "CredentialStatusRegistry"
    );

  const registry =
    Registry.attach(
      STATUS_REGISTRY_ADDRESS
    );

  const credentialHash =
    ethers.keccak256(
      ethers.toUtf8Bytes(
        CREDENTIAL_ID
      )
    );

  console.log(
    "Registering credential..."
  );

  console.log(
    "Registry:",
    STATUS_REGISTRY_ADDRESS
  );

  console.log(
    "Sender:",
    account.address
  );

  console.log(
    "Credential ID:",
    CREDENTIAL_ID
  );

  console.log(
    "Credential hash:",
    credentialHash
  );

  const alreadyRegistered =
    await registry
      .isCredentialRegistered(
        credentialHash
      );

  if (alreadyRegistered) {

    console.log(
      "\nCredential is already registered."
    );

  } else {

    const transaction =
      await registry
        .registerCredential(
          credentialHash
        );

    console.log(
      "\nTransaction hash:",
      transaction.hash
    );

    const receipt =
      await transaction.wait();

    if (
      receipt === null
      || receipt.status !== 1
    ) {
      throw new Error(
        "Credential registration transaction failed."
      );
    }

    console.log(
      "Registration transaction confirmed."
    );
  }

  const registered =
    await registry
      .isCredentialRegistered(
        credentialHash
      );

  const revoked =
    await registry
      .isCredentialRevoked(
        credentialHash
      );

  const valid =
    await registry
      .isCredentialValid(
        credentialHash
      );

  const status =
    await registry
      .getCredentialStatus(
        credentialHash
      );

  console.log(
    "\nON-CHAIN CREDENTIAL STATUS"
  );

  console.log(
    "Registered:",
    registered
  );

  console.log(
    "Revoked:",
    revoked
  );

  console.log(
    "Valid:",
    valid
  );

  console.log(
    "Registered at:",
    status[2].toString()
  );

  console.log(
    "Revoked at:",
    status[3].toString()
  );
}


main().catch(
  (error) => {

    console.error(
      error
    );

    process.exitCode = 1;
  }
);
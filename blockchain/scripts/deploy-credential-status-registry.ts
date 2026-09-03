import { network } from "hardhat";

async function main() {

  const { ethers } =
    await network.getOrCreate();

  const [deployer] =
    await ethers.getSigners();

  console.log(
    "Deploying CredentialStatusRegistry..."
  );

  console.log(
    "Deployer:",
    deployer.address
  );

  const Registry =
    await ethers.getContractFactory(
      "CredentialStatusRegistry"
    );

  const registry =
    await Registry.deploy();

  await registry.waitForDeployment();

  const address =
    await registry.getAddress();

  console.log(
    "CredentialStatusRegistry deployed to:",
    address
  );

  console.log(
    "Registry owner:",
    await registry.owner()
  );
}

main().catch(
  (error) => {
    console.error(error);
    process.exitCode = 1;
  }
);
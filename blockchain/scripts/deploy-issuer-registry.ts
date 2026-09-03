import { network } from "hardhat";

async function main() {
  const { ethers } =
    await network.getOrCreate();

  const [deployer] =
    await ethers.getSigners();

  console.log(
    "Deploying IssuerRegistry..."
  );

  console.log(
    "Deployer:",
    deployer.address
  );

  const registry =
    await ethers.deployContract(
      "IssuerRegistry"
    );

  await registry.waitForDeployment();

  const address =
    await registry.getAddress();

  console.log(
    "IssuerRegistry deployed to:",
    address
  );

  console.log(
    "Registry owner:",
    await registry.owner()
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
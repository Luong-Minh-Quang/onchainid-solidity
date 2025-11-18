import {task} from "hardhat/config";
import {TaskArguments} from "hardhat/types";

task("deploy-claim-issuer", "Deploy a claim issuer as a standalone contract")
  .addParam("from", "Will pay the gas for the transaction")
  .addParam("key", "The ethereum address that will own the identity (as a MANAGEMENT key)")
  .setAction(async (args: TaskArguments, hre) => {
    const signer = await hre.ethers.getSigner(args.from);

    const identity = await hre.ethers.deployContract('ClaimIssuer', [args.key], signer);

    console.log(`Deploy a new claim issuer at ${identity.address} . tx: ${identity.deployTransaction.hash}`);

    await identity.deployed();

    console.log(`Deployed a new claim issuer at ${identity.address} . tx: ${identity.deployTransaction.hash}`);
  });

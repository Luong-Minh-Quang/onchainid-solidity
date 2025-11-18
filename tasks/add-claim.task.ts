import {task} from "hardhat/config";
import {TaskArguments} from "hardhat/types";

task("add-claim", "Add a claim to an identity")
  .addParam("identity", "The address of the identity")
  .addParam("from", "A CLAIM key on the claim issuer")
  .addParam("claim", "The content of a claim as a JSON string")
  .setAction(async (args: TaskArguments, hre) => {
    const signer = await hre.ethers.getSigner(args.from);

    // Load identity contract
    const identity = await hre.ethers.getContractAt("Identity", args.identity, signer);

    // Load JSON from file
    const fs = require("fs");
    const claim = JSON.parse(fs.readFileSync(args.claim));

    // Convert topic string → bytes32 hash
    const topicHash = hre.ethers.utils.id(claim.topic);

    // Convert data string → bytes
    const dataBytes = hre.ethers.utils.toUtf8Bytes(claim.data);
    const dataHex = hre.ethers.utils.hexlify(dataBytes);

    // Create digest required by ERC-735
    const digest = hre.ethers.utils.keccak256(
      hre.ethers.utils.defaultAbiCoder.encode(
        ["address", "uint256", "bytes"],
        [args.identity, topicHash, dataHex]
      )
    );

    // Sign digest with the issuer key
    const signature = await signer.signMessage(hre.ethers.utils.arrayify(digest));

    // Use issuer from signer unless overridden in JSON
    const issuer = claim.issuer || args.from;

    console.log("Prepared claim:");
    console.log({
      topicHash,
      scheme: claim.scheme,
      issuer,
      signature,
      dataHex,
      uri: claim.uri
    });

    // Send tx
    const tx = await identity.addClaim(
      topicHash,
      claim.scheme,
      issuer,
      signature,
      dataHex,
      claim.uri
    );

    console.log(`⏳ Adding claim... tx: ${tx.hash}`);
    await tx.wait();
    console.log(`✅ Claim added. tx mined: ${tx.hash}`);
  });

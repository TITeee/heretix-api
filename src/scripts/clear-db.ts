import 'dotenv/config';
import { prisma } from '../db/client.js';

async function main() {
  const d1 = await prisma.oSVAffectedPackage.deleteMany();
  const d2 = await prisma.nVDAffectedPackage.deleteMany();
  const d3 = await prisma.advisoryAffectedProduct.deleteMany();
  const d4 = await prisma.oSVVulnerability.deleteMany();
  const d5 = await prisma.nVDVulnerability.deleteMany();
  const d6 = await prisma.advisoryVulnerability.deleteMany();
  const d7 = await prisma.vulnerability.deleteMany();
  const d8 = await prisma.collectionJob.deleteMany();
  console.log(`OSVAffectedPackage: ${d1.count} deleted`);
  console.log(`NVDAffectedPackage: ${d2.count} deleted`);
  console.log(`AdvisoryAffectedProduct: ${d3.count} deleted`);
  console.log(`OSVVulnerability: ${d4.count} deleted`);
  console.log(`NVDVulnerability: ${d5.count} deleted`);
  console.log(`AdvisoryVulnerability: ${d6.count} deleted`);
  console.log(`Vulnerability: ${d7.count} deleted`);
  console.log(`CollectionJob: ${d8.count} deleted`);
  await prisma.$disconnect();
}

main();

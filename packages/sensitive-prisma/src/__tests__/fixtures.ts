import { PrismaBetterSqlite3 } from '@prisma/adapter-better-sqlite3';
import { PrismaClient } from '../../generated/prisma/client.js';

/**
 * The canary every test in this package writes and looks for.
 *
 * One conspicuous constant so a leak is greppable in any output: a log line, a
 * serialised payload, an error message, or a column in the database.
 */
export const CANARY = 'LEAKED_SECRET_abc123xyz';

/**
 * Schema for the in-memory database each test runs against.
 *
 * Written by hand rather than pushed by the Prisma CLI, because `prisma db
 * push` needs a file on disk and a config module, and a file shared between
 * Vitest workers is not isolation. Drift from `prisma/schema.prisma` cannot go
 * unnoticed: every test drives real queries through Prisma, which validates
 * against the generated client and fails on a column that is missing or named
 * differently.
 */
const DDL = [
  `CREATE TABLE "User" (
     "id" INTEGER PRIMARY KEY AUTOINCREMENT,
     "email" TEXT NOT NULL UNIQUE,
     "passwordHash" TEXT NOT NULL,
     "name" TEXT NOT NULL,
     "nickname" TEXT
   )`,
  `CREATE TABLE "Post" (
     "id" INTEGER PRIMARY KEY AUTOINCREMENT,
     "title" TEXT NOT NULL,
     "secret" TEXT NOT NULL,
     "authorId" INTEGER NOT NULL,
     FOREIGN KEY ("authorId") REFERENCES "User"("id") ON DELETE CASCADE
   )`,
  `CREATE TABLE "PaymentMethod" (
     "id" INTEGER PRIMARY KEY AUTOINCREMENT,
     "cardNumber" TEXT NOT NULL,
     "cardCvv" TEXT NOT NULL,
     "cardExpiry" TEXT NOT NULL,
     "balance" DECIMAL NOT NULL,
     "token" BLOB NOT NULL,
     "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
     "ownerId" INTEGER NOT NULL,
     FOREIGN KEY ("ownerId") REFERENCES "User"("id") ON DELETE CASCADE
   )`,
] as const;

/**
 * A fresh, empty database and an unextended client over it.
 *
 * In-memory and per call, so tests share no rows and can run in parallel.
 */
export async function createBaseClient(
  options: Record<string, unknown> = {}
): Promise<PrismaClient> {
  const adapter = new PrismaBetterSqlite3({ url: ':memory:' });
  const client = new PrismaClient({ adapter, ...options });

  for (const statement of DDL) {
    await client.$executeRawUnsafe(statement);
  }

  return client;
}

/**
 * Read a column with no extension in the way.
 *
 * The point of the marker tests: what the extension published is not evidence
 * about what the driver was handed. This reads the bytes the database actually
 * holds.
 */
export async function readColumn(
  client: PrismaClient,
  table: string,
  column: string,
  id: number
): Promise<unknown> {
  const rows = await client.$queryRawUnsafe<Record<string, unknown>[]>(
    `SELECT "${column}" AS value FROM "${table}" WHERE "id" = ?`,
    id
  );
  return rows[0]?.['value'];
}

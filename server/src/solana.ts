import { Connection, PublicKey, SystemProgram, Transaction, TransactionInstruction } from '@solana/web3.js';
import { config } from './config.js';

let cachedConnection: Connection | null = null;

export function getConnection(): Connection {
  if (cachedConnection) return cachedConnection;
  cachedConnection = new Connection(config.solana.rpcUrl, 'confirmed');
  return cachedConnection;
}

export async function buildUnsignedTransfer(
  fromAddress: string,
  toAddress: string,
  lamports: bigint,
  memo?: string
): Promise<{ tx: Transaction; recentBlockhash: string }> {
  const connection = getConnection();
  const lamportsNum = Number(lamports);
  if (!Number.isSafeInteger(lamportsNum) || lamportsNum <= 0) {
    throw new Error('Invalid lamports amount');
  }

  const { blockhash } = await connection.getLatestBlockhash('finalized');
  const tx = new Transaction();
  tx.feePayer = new PublicKey(fromAddress);
  tx.recentBlockhash = blockhash;

  tx.add(
    SystemProgram.transfer({
      fromPubkey: new PublicKey(fromAddress),
      toPubkey: new PublicKey(toAddress),
      lamports: lamportsNum
    })
  );

  if (memo) {
    tx.add(
      new TransactionInstruction({
        keys: [],
        programId: new PublicKey('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'),
        data: Buffer.from(memo, 'utf8')
      })
    );
  }

  return { tx, recentBlockhash: blockhash };
}

export function serializeUnsignedTransaction(tx: Transaction): string {
  return tx.serialize({ requireAllSignatures: false, verifySignatures: false }).toString('base64');
}

export async function relaySignedTransaction(base64Tx: string): Promise<string> {
  const connection = getConnection();
  const raw = Buffer.from(base64Tx, 'base64');
  const signature = await connection.sendRawTransaction(raw, { skipPreflight: false });
  await connection.confirmTransaction(signature, 'confirmed');
  return signature;
}

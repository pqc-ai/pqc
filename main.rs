use sha2::{Sha256, Digest};
use oqs::sig::{Sig, Algorithm};
use serde::{Serialize, Deserialize};
use thiserror::Error;

// ================= ERROR =================

#[derive(Error, Debug)]
pub enum ChainError {
    #[error("PQC init gagal")]
    PQCInit,

    #[error("Keypair gagal")]
    Keypair,

    #[error("Sign gagal")]
    Sign,

    #[error("Serialize gagal")]
    Serialize,
}

// ================= PQC =================

pub struct PQC {
    sigalg: Sig,
}

impl PQC {
    pub fn new() -> Result<Self, ChainError> {
        let sigalg = Sig::new(Algorithm::Dilithium2)
            .map_err(|_| ChainError::PQCInit)?;
        Ok(Self { sigalg })
    }

    pub fn keypair(&self) -> Result<(Vec<u8>, Vec<u8>), ChainError> {
        self.sigalg.keypair().map_err(|_| ChainError::Keypair)
    }

    pub fn sign(&self, data: &[u8], sk: &[u8]) -> Result<Vec<u8>, ChainError> {
        self.sigalg.sign(data, sk).map_err(|_| ChainError::Sign)
    }

    pub fn verify(&self, data: &[u8], sig: &[u8], pk: &[u8]) -> bool {
        self.sigalg.verify(data, sig, pk).is_ok()
    }
}

// ================= WALLET =================

#[derive(Clone)]
pub struct Wallet {
    pub public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl Wallet {
    pub fn new(pqc: &PQC) -> Result<Self, ChainError> {
        let (pk, sk) = pqc.keypair()?;
        Ok(Self {
            public_key: pk,
            secret_key: sk,
        })
    }

    pub fn sign(&self, pqc: &PQC, data: &[u8]) -> Result<Vec<u8>, ChainError> {
        pqc.sign(data, &self.secret_key)
    }
}

// ================= TRANSACTION =================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub from: Vec<u8>,
    pub data: String,
    pub signature: Vec<u8>,
}

impl Transaction {
    pub fn hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(&self.from);
        hasher.update(self.data.as_bytes());
        hasher.finalize().to_vec()
    }

    pub fn verify(&self, pqc: &PQC) -> bool {
        pqc.verify(&self.hash(), &self.signature, &self.from)
    }
}

// ================= BLOCK =================

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub index: u32,
    pub previous_hash: String,
    pub hash: String,
    pub transactions: Vec<Transaction>,
    pub nonce: u64,
}

impl Block {
    pub fn calculate_hash(
        index: u32,
        prev: &str,
        txs: &Vec<Transaction>,
        nonce: u64,
    ) -> Result<String, ChainError> {
        let data = serde_json::to_string(txs)
            .map_err(|_| ChainError::Serialize)?;

        let input = format!("{}{}{}{}", index, prev, data, nonce);

        let mut hasher = Sha256::new();
        hasher.update(input);

        Ok(format!("{:x}", hasher.finalize()))
    }

    pub fn mine(
        index: u32,
        prev: String,
        txs: Vec<Transaction>,
        difficulty: usize,
    ) -> Result<Self, ChainError> {
        let mut nonce = 0;

        loop {
            let hash = Self::calculate_hash(index, &prev, &txs, nonce)?;

            if hash.starts_with(&"0".repeat(difficulty)) {
                return Ok(Self {
                    index,
                    previous_hash: prev,
                    hash,
                    transactions: txs,
                    nonce,
                });
            }

            nonce += 1;
        }
    }
}

// ================= BLOCKCHAIN =================

pub struct Blockchain {
    pub chain: Vec<Block>,
    difficulty: usize,
}

impl Blockchain {
    pub fn new(difficulty: usize) -> Result<Self, ChainError> {
        let genesis = Block::mine(0, "0".into(), vec![], difficulty)?;
        Ok(Self {
            chain: vec![genesis],
            difficulty,
        })
    }

    pub fn add_block(&mut self, txs: Vec<Transaction>) -> Result<(), ChainError> {
        let last_hash = self.chain.last()
            .ok_or(ChainError::Serialize)?
            .hash
            .clone();

        let block = Block::mine(
            self.chain.len() as u32,
            last_hash,
            txs,
            self.difficulty,
        )?;

        self.chain.push(block);
        Ok(())
    }

    pub fn is_valid(&self, pqc: &PQC) -> bool {
        for i in 0..self.chain.len() {
            let block = &self.chain[i];

            // cek hash
            let recalculated = match Block::calculate_hash(
                block.index,
                &block.previous_hash,
                &block.transactions,
                block.nonce,
            ) {
                Ok(h) => h,
                Err(_) => return false,
            };

            if block.hash != recalculated {
                return false;
            }

            // cek link
            if i > 0 && block.previous_hash != self.chain[i - 1].hash {
                return false;
            }

            // cek transaksi
            for tx in &block.transactions {
                if !tx.verify(pqc) {
                    return false;
                }
            }
        }

        true
    }
}

// ================= MAIN =================

fn main() -> Result<(), ChainError> {
    let pqc = PQC::new()?;

    let wallet = Wallet::new(&pqc)?;

    // buat transaksi
    let message = b"Transfer PQC Data";
    let signature = wallet.sign(&pqc, message)?;

    let tx = Transaction {
        from: wallet.public_key.clone(),
        data: "Transfer PQC Data".into(),
        signature,
    };

    // blockchain
    let mut chain = Blockchain::new(3)?;

    chain.add_block(vec![tx.clone()])?;
    chain.add_block(vec![tx])?;

    println!("=== PQC BLOCKCHAIN FINAL ===");
    println!("Jumlah block: {}", chain.chain.len());
    println!("Valid: {}", chain.is_valid(&pqc));

    Ok(())
          }

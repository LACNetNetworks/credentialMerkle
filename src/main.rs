mod algorithms;

extern crate rs_merkle;
extern crate hex;

use std::{io};
use rs_merkle::*;
use rs_merkle::{algorithms::Sha256};

use crate::algorithms::Keccak256;
fn main() -> Result<(), io::Error> {
    let leaf_values = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "aa", "ab", "ac", "ad", "ae", "af", "ag", "ah", "ai", "aj", "ak", "al", "am", "an", "ao", "ap", "aq", "ar", "as", "at", "au", "av", "aw", "ax", "ay", "az", "ba", "bb", "bc", "bd", "be", "bf", "bg", "bh", "bi", "bj", "bk", "bl", "bm", "bn", "bo", "bp", "bq", "br", "bs", "bt", "bu", "bv", "bw", "bx", "by", "bz", "ca", "cb", "cc", "cd", "ce", "cf", "cg", "ch", "ci", "cj", "ck", "cl", "cm", "cn", "co", "cp", "cq", "cr", "cs", "ct", "cu", "cv", "cw", "cx", "cy", "cz"];
//    let leaf_values = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k"];
    let leaves: Vec<[u8; 32]> = leaf_values
        .iter()
        .map(|x| Keccak256::hash(x.as_bytes()))
        .collect();

    let mut merkle_tree = MerkleTree::<Keccak256>::from_leaves(&leaves);
    let indices_to_prove = vec![0];
    let leaves_to_prove = leaves.get(0..1).ok_or("can't get leaves to prove").expect("can't");
    let merkle_proof = merkle_tree.proof(&indices_to_prove);
    let merkle_root = merkle_tree.root().ok_or("couldn't get the merkle root").expect("couldn't");
    // Serialize proof to pass it to the client
    let proof_bytes = merkle_proof.to_bytes();

    println!("proof bytes: {}",hex::encode(&proof_bytes));
    println!("proof len: {}",proof_bytes.len()/32);
    
    // Parse proof back on the client
    let proof = MerkleProof::<Keccak256>::try_from(proof_bytes).expect("as");

    println!("root: {:?}",merkle_tree.root_hex());
    println!("Depth: {}",merkle_tree.depth());
    println!("{:x?}",&indices_to_prove);
    println!("{:x?}",leaves_to_prove);
    println!("leaves {:x?}", merkle_tree.leaves());

    assert!(proof.verify(merkle_root, &indices_to_prove, leaves_to_prove, leaves.len()),"no es correcto");
    /*
    merkle_tree
        .insert(Keccak256::hash("ab".as_bytes()))
        .commit();

    println!("root: {:?}",merkle_tree.root_hex());
    println!("leaves {:x?}", merkle_tree.leaves());

    //let merkle_root = merkle_tree.root().ok_or("couldn't get the merkle root").expect("couldn't");
    */
    if proof.verify(merkle_root, &indices_to_prove, leaves_to_prove, leaves.len()){
        println!("correcto");
    }else{
        println!("incorrecto");
    }
    
    return Ok(());
}

fn commit_proof(){
    let elements = ["a", "b", "c", "d", "e", "f"];
    let mut leaves: Vec<[u8; 32]> = elements
        .iter()
        .map(|x| Sha256::hash(x.as_bytes()))
        .collect();

    let mut merkle_tree: MerkleTree<Sha256> = MerkleTree::new();

    // Appending leaves to the tree without committing
    merkle_tree.append(&mut leaves);

    // Without committing changes we can get the root for the uncommitted data, but committed
    // tree still doesn't have any elements
    assert_eq!(merkle_tree.root(), None);
    assert_eq!(
        merkle_tree.uncommitted_root_hex(),
        Some("1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2".to_string())
    );

    // Committing the changes
    merkle_tree.commit();

    // Changes applied to the tree after the commit, and there's no uncommitted changes anymore
    assert_eq!(
        merkle_tree.root_hex(),
        Some("1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2".to_string())
    );
    assert_eq!(merkle_tree.uncommitted_root_hex(), None);

    // Adding a new leaf
    merkle_tree.insert(Sha256::hash("g".as_bytes())).commit();

    // Root was updated after insertion
    assert_eq!(
        merkle_tree.root_hex(),
        Some("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034".to_string())
    );

    // Adding some more leaves
    merkle_tree.append(vec![
        Sha256::hash("h".as_bytes()),
        Sha256::hash("k".as_bytes()),
    ].as_mut()).commit();
    assert_eq!(
        merkle_tree.root_hex(),
        Some("09b6890b23e32e607f0e5f670ab224e36af8f6599cbe88b468f4b0f761802dd6".to_string())
    );

    // Rolling back to the previous state
    merkle_tree.rollback();
    assert_eq!(
        merkle_tree.root_hex(),
        Some("e2a80e0e872a6c6eaed37b4c1f220e1935004805585b5f99617e48e9c8fe4034".to_string())
    );

    // We can rollback multiple times as well
    merkle_tree.rollback();
    assert_eq!(
        merkle_tree.root_hex(),
        Some("1f7379539707bcaea00564168d1d4d626b09b73f8a2a365234c62d763f854da2".to_string())
    );
}

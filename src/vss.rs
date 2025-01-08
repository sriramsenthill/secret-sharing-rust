// File: src/vss.rs
use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;
use std::ops::Mul;

#[derive(Clone, Debug)]
pub struct Share {
    pub id: BigUint,
    pub value: BigUint,
}

#[derive(Clone, Debug)]
pub struct Commitment(pub Vec<BigUint>);

#[derive(Debug)]
struct VSSParams {
    p: BigUint, // Prime field modulus
    q: BigUint, // Prime order of generator
    g: BigUint, // Generator
    threshold: usize,
    total_shares: usize,
}

pub struct FeldmanVSS {
    params: VSSParams,
    rng: rand::rngs::ThreadRng,
}

impl FeldmanVSS {
    pub fn new(p: BigUint, q: BigUint, g: BigUint, threshold: usize, total_shares: usize) -> Self {
        if threshold > total_shares {
            panic!("Threshold must be less than or equal to total shares");
        }

        FeldmanVSS {
            params: VSSParams {
                p,
                q,
                g,
                threshold,
                total_shares,
            },
            rng: thread_rng(),
        }
    }

    pub fn split_secret(
        &mut self,
        secret: &BigUint,
    ) -> Result<(Vec<Share>, Commitment), &'static str> {
        if secret >= &self.params.q {
            return Err("Secret must be less than q");
        }

        let coefficients = self.generate_polynomial(secret);
        let commitments = self.generate_commitments(&coefficients);
        let shares = self.generate_shares(&coefficients);

        Ok((shares, commitments))
    }

    pub fn verify_share(&self, share: &Share, commitments: &Commitment) -> bool {
        let lhs = self.compute_commitment_product(share, commitments);
        let rhs = self.params.g.modpow(&share.value, &self.params.p);
        lhs == rhs
    }

    pub fn reconstruct_secret(&self, shares: &[Share]) -> Option<BigUint> {
        if shares.len() < self.params.threshold {
            return None;
        }

        let shares = &shares[0..self.params.threshold];
        shares
            .iter()
            .enumerate()
            .try_fold(BigUint::zero(), |acc, (i, share)| {
                self.calculate_lagrange_coefficient(share, shares, i)
                    .map(|coeff| (acc + &share.value * coeff) % &self.params.q)
            })
    }

    fn generate_polynomial(&mut self, secret: &BigUint) -> Vec<BigUint> {
        let mut coefficients = vec![secret.clone()];
        for _ in 1..self.params.threshold {
            coefficients.push(self.rng.gen_biguint_range(&BigUint::zero(), &self.params.q));
        }
        coefficients
    }

    fn generate_commitments(&self, coefficients: &[BigUint]) -> Commitment {
        Commitment(
            coefficients
                .iter()
                .map(|coeff| self.params.g.modpow(coeff, &self.params.p))
                .collect(),
        )
    }

    fn generate_shares(&self, coefficients: &[BigUint]) -> Vec<Share> {
        (1..=self.params.total_shares)
            .map(|i| {
                let id = BigUint::from(i as u32);
                let value = self.evaluate_polynomial(coefficients, &id);
                Share { id, value }
            })
            .collect()
    }

    fn evaluate_polynomial(&self, coefficients: &[BigUint], x: &BigUint) -> BigUint {
        coefficients
            .iter()
            .enumerate()
            .fold(BigUint::zero(), |acc, (power, coeff)| {
                let term = coeff * x.modpow(&BigUint::from(power as u32), &self.params.q);
                (acc + term) % &self.params.q
            })
    }

    fn compute_commitment_product(&self, share: &Share, commitments: &Commitment) -> BigUint {
        commitments
            .0
            .iter()
            .enumerate()
            .fold(BigUint::one(), |acc, (power, commitment)| {
                let x_power = share
                    .id
                    .modpow(&BigUint::from(power as u32), &self.params.q);
                let term = commitment.modpow(&x_power, &self.params.p);
                (acc * term) % &self.params.p
            })
    }

    fn calculate_lagrange_coefficient(
        &self,
        share_i: &Share,
        shares: &[Share],
        i: usize,
    ) -> Option<BigUint> {
        let (numerator, denominator) = shares.iter().enumerate().filter(|&(j, _)| i != j).fold(
            (BigUint::one(), BigUint::one()),
            |(num, den), (_, share_j)| {
                let new_num = (num * &share_j.id) % &self.params.q;
                let diff = if share_j.id > share_i.id {
                    (&share_j.id - &share_i.id) % &self.params.q
                } else {
                    (&self.params.q + &share_j.id - &share_i.id) % &self.params.q
                };
                let new_den = (den * diff) % &self.params.q;
                (new_num, new_den)
            },
        );

        self.mod_inverse(&denominator)
            .map(|den_inv| (numerator * den_inv) % &self.params.q)
    }

    fn mod_inverse(&self, a: &BigUint) -> Option<BigUint> {
        if a.is_zero() {
            return None;
        }
        Some(a.modpow(&(&self.params.q - 2u32), &self.params.q))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigUint;

    #[test]
    fn test_vss_workflow() {
        let p = 23u32.to_biguint().unwrap();
        let q = 11u32.to_biguint().unwrap();
        let g = 2u32.to_biguint().unwrap();
        let threshold = 3;
        let total_shares = 5;

        let mut vss = FeldmanVSS::new(p, q, g, threshold, total_shares);
        let secret = 7u32.to_biguint().unwrap();

        let (shares, commitments) = vss.split_secret(&secret).unwrap();

        // Verify all shares
        assert!(shares
            .iter()
            .all(|share| vss.verify_share(share, &commitments)));

        // Test reconstruction
        let reconstructed = vss.reconstruct_secret(&shares[0..threshold]);
        assert_eq!(reconstructed, Some(secret));

        // Test insufficient shares
        let insufficient = vss.reconstruct_secret(&shares[0..threshold - 1]);
        assert_eq!(insufficient, None);
    }
}

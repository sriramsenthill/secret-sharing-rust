use num_bigint::{BigUint, RandBigInt};
use num_traits::{One, Zero};
use rand::thread_rng;

#[derive(Debug, Clone)]
pub struct Share {
    pub x: BigUint,
    pub y: BigUint,
}

pub struct SecretSharer {
    prime: BigUint,
    threshold: usize,
    total_shares: usize,
}

impl SecretSharer {
    pub fn new(threshold: usize, total_shares: usize) -> Self {
        // Using a 521-bit prime for better security
        let prime = BigUint::from(2u32).pow(521) - BigUint::from(1u32);
        SecretSharer {
            prime,
            threshold,
            total_shares,
        }
    }

    pub fn split_secret(&self, secret: &BigUint) -> Vec<Share> {
        let mut rng = thread_rng();
        let mut coefficients = vec![secret.clone() % &self.prime];

        // Generate random coefficients
        for _ in 1..self.threshold {
            coefficients.push(rng.gen_biguint_range(&BigUint::zero(), &self.prime));
        }

        // Generate shares
        (1..=self.total_shares)
            .map(|x| {
                let x = BigUint::from(x as u32);
                let y = self.evaluate_polynomial(&coefficients, &x);
                Share { x, y }
            })
            .collect()
    }

    pub fn reconstruct_secret(&self, shares: &[Share]) -> Option<BigUint> {
        if shares.len() < self.threshold {
            return None;
        }

        let shares = &shares[..self.threshold];
        let mut secret = BigUint::zero();

        for (i, share_i) in shares.iter().enumerate() {
            let lagrange_coeff = self.calculate_lagrange_coefficient(share_i, shares, i)?;
            secret = (secret + (&share_i.y * &lagrange_coeff)) % &self.prime;
        }

        Some(secret)
    }

    fn evaluate_polynomial(&self, coefficients: &[BigUint], x: &BigUint) -> BigUint {
        coefficients
            .iter()
            .enumerate()
            .fold(BigUint::zero(), |acc, (power, coeff)| {
                let term = coeff * x.modpow(&BigUint::from(power as u32), &self.prime);
                (acc + term) % &self.prime
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
                let new_num = (num * &share_j.x) % &self.prime;
                let diff = if &share_j.x > &share_i.x {
                    (&share_j.x - &share_i.x) % &self.prime
                } else {
                    (&self.prime + &share_j.x - &share_i.x) % &self.prime
                };
                let new_den = (den * diff) % &self.prime;
                (new_num, new_den)
            },
        );

        self.mod_inverse(&denominator)
            .map(|den_inv| (numerator * den_inv) % &self.prime)
    }

    fn mod_inverse(&self, a: &BigUint) -> Option<BigUint> {
        if a.is_zero() {
            return None;
        }
        Some(a.modpow(&(&self.prime - 2u32), &self.prime))
    }
}

use crate::{
    lms::{
        self,
        definitions::{LmsPrivateKey, LmsPublicKey},
        generate_key_pair,
        signing::LmsSignature,
    },
    util::dynamic_array::DynamicArray,
    LmotsParameter, LmsParameter,
};

#[derive(Default)]
pub struct HssPrivateKey<OTS: LmotsParameter, LMS: LmsParameter, const L: usize> {
    private_key: DynamicArray<LmsPrivateKey<OTS, LMS>, L>,
    public_key: DynamicArray<LmsPublicKey<OTS, LMS>, L>,
    signatures: DynamicArray<LmsSignature<OTS, LMS>, L>, // Only L - 1 signatures needed
}

impl<OTS: LmotsParameter, LMS: LmsParameter, const L: usize> HssPrivateKey<OTS, LMS, L> {
    fn generate() -> Self {
        let mut hss_private_key: HssPrivateKey<OTS, LMS, L> = Default::default();

        let lms_keypair = generate_key_pair();

        hss_private_key.private_key.push(lms_keypair.private_key);
        hss_private_key.public_key.push(lms_keypair.public_key);

        for i in 1..L {
            let lms_keypair = generate_key_pair();

            hss_private_key.private_key.push(lms_keypair.private_key);
            hss_private_key.public_key.push(lms_keypair.public_key);

            let signature = lms::signing::LmsSignature::sign(
                &mut hss_private_key.private_key[i],
                hss_private_key.public_key[i]
                    .to_binary_representation()
                    .as_slice(),
            );
        }

        hss_private_key
    }
}

pub struct HssPublicKey<const L: usize> {}

pub struct HssSignature<const L: usize> {}

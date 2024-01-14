#![feature(test)]
extern crate test;

#[cfg(test)]
mod tests {
    use rand::{rngs::OsRng, RngCore};
    use test::Bencher;
    use tinyvec::ArrayVec;

    use hbs_lms::sst::parameters::SstsParameter;
    use hbs_lms::{keygen, HssParameter, LmotsAlgorithm, LmsAlgorithm, Seed, Sha256_256};
    use hbs_lms::{
        signature::{SignerMut, Verifier},
        Signature, SigningKey, VerifierSignature, VerifyingKey,
    };

    const MESSAGE: [u8; 17] = [
        32u8, 48, 2, 1, 48, 58, 20, 57, 9, 83, 99, 255, 0, 34, 2, 1, 0,
    ];

    fn generate_signing_key(
        hss_parameter: &[HssParameter<Sha256_256>],
        aux_data: Option<&mut &mut [u8]>,
    ) -> SigningKey<Sha256_256> {
        let mut seed = Seed::default();
        OsRng.fill_bytes(seed.as_mut_slice());

        let mut vec_hss_params: ArrayVec<[_; hbs_lms::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]> =
            Default::default();
        for i in 0..hss_parameter.len() {
            vec_hss_params.push(hss_parameter[i]);
        }

        let sst_param = SstsParameter::<Sha256_256>::new(vec_hss_params, 0, 0);

        let (signing_key, _) = keygen::<Sha256_256>(&sst_param, &seed, aux_data).unwrap();

        signing_key
    }

    fn generate_verifying_key_and_signature() -> (VerifyingKey<Sha256_256>, Signature) {
        let mut seed = Seed::default();
        OsRng.fill_bytes(seed.as_mut_slice());

        let mut vec_hss_params: ArrayVec<[_; hbs_lms::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]> =
            Default::default();
        vec_hss_params.push(HssParameter::new(
            LmotsAlgorithm::LmotsW2,
            LmsAlgorithm::LmsH5,
        ));
        let sst_param = SstsParameter::<Sha256_256>::new(vec_hss_params, 0, 0);

        let (mut signing_key, verifying_key) =
            keygen::<Sha256_256>(&sst_param, &seed, None).unwrap();

        let signature = signing_key.try_sign(&MESSAGE).unwrap();

        (verifying_key, signature)
    }

    #[bench]
    fn keygen_h5w2(b: &mut Bencher) {
        let mut seed = Seed::default();
        OsRng.fill_bytes(seed.as_mut_slice());
        let mut vec_hss_params: ArrayVec<[_; hbs_lms::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]> =
            Default::default();
        vec_hss_params.push(HssParameter::new(
            LmotsAlgorithm::LmotsW2,
            LmsAlgorithm::LmsH5,
        ));
        let sst_param = SstsParameter::<Sha256_256>::new(vec_hss_params, 0, 0);

        b.iter(|| {
            let _ = keygen::<Sha256_256>(&sst_param, &seed, None);
        });
    }

    #[bench]
    fn keygen_with_aux_h5w2(b: &mut Bencher) {
        let mut seed = Seed::default();
        OsRng.fill_bytes(seed.as_mut_slice());

        let mut vec_hss_params: ArrayVec<[_; hbs_lms::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]> =
            Default::default();
        vec_hss_params.push(HssParameter::new(
            LmotsAlgorithm::LmotsW2,
            LmsAlgorithm::LmsH5,
        ));
        let sst_param = SstsParameter::<Sha256_256>::new(vec_hss_params, 0, 0);

        b.iter(|| {
            let mut aux_data = vec![0u8; 100_000];
            let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];

            let _ = keygen::<Sha256_256>(&sst_param, &seed, Some(aux_slice));
        });
    }

    #[bench]
    fn keygen_h5w2_h5w2(b: &mut Bencher) {
        let mut seed = Seed::default();
        OsRng.fill_bytes(seed.as_mut_slice());

        let mut vec_hss_params: ArrayVec<[_; hbs_lms::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]> =
            Default::default();
        vec_hss_params.push(HssParameter::new(
            LmotsAlgorithm::LmotsW2,
            LmsAlgorithm::LmsH5,
        ));
        vec_hss_params.push(HssParameter::new(
            LmotsAlgorithm::LmotsW2,
            LmsAlgorithm::LmsH5,
        ));
        let sst_param = SstsParameter::<Sha256_256>::new(vec_hss_params, 0, 0);

        b.iter(|| {
            let _ = keygen::<Sha256_256>(&sst_param, &seed, None);
        });
    }

    #[bench]
    fn keygen_with_aux_h5w2_h5w2(b: &mut Bencher) {
        let mut seed = Seed::default();
        OsRng.fill_bytes(seed.as_mut_slice());

        let mut vec_hss_params: ArrayVec<[_; hbs_lms::REF_IMPL_MAX_ALLOWED_HSS_LEVELS]> =
            Default::default();
        vec_hss_params.push(HssParameter::new(
            LmotsAlgorithm::LmotsW2,
            LmsAlgorithm::LmsH5,
        ));
        vec_hss_params.push(HssParameter::new(
            LmotsAlgorithm::LmotsW2,
            LmsAlgorithm::LmsH5,
        ));
        let sst_param = SstsParameter::<Sha256_256>::new(vec_hss_params, 0, 0);

        b.iter(|| {
            let mut aux_data = vec![0u8; 100_000];
            let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];

            let _ = keygen::<Sha256_256>(&sst_param, &seed, Some(aux_slice));
        });
    }

    #[bench]
    fn sign_h5w2(b: &mut Bencher) {
        let hss_parameter = [HssParameter::new(
            LmotsAlgorithm::LmotsW2,
            LmsAlgorithm::LmsH5,
        )];
        let signing_key = generate_signing_key(&hss_parameter, None);

        b.iter(|| {
            let mut signing_key = signing_key.clone();
            signing_key.try_sign(&MESSAGE).unwrap()
        });
    }

    #[bench]
    fn sign_with_aux_h5w2(b: &mut Bencher) {
        let hss_parameter = [HssParameter::new(
            LmotsAlgorithm::LmotsW2,
            LmsAlgorithm::LmsH5,
        )];
        let mut aux_data = vec![0u8; 100_000];
        let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];
        let signing_key = generate_signing_key(&hss_parameter, Some(aux_slice));

        b.iter(|| {
            let mut signing_key = signing_key.clone();
            signing_key
                .try_sign_with_aux(&MESSAGE, Some(aux_slice))
                .unwrap()
        });
    }

    #[bench]
    fn sign_with_aux_h10w2(b: &mut Bencher) {
        let hss_parameter = [HssParameter::new(
            LmotsAlgorithm::LmotsW2,
            LmsAlgorithm::LmsH10,
        )];
        let mut aux_data = vec![0u8; 100_000];
        let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];
        let signing_key = generate_signing_key(&hss_parameter, Some(aux_slice));

        b.iter(|| {
            let mut signing_key = signing_key.clone();
            signing_key
                .try_sign_with_aux(&MESSAGE, Some(aux_slice))
                .unwrap()
        });
    }

    #[bench]
    fn sign_with_aux_h15w2(b: &mut Bencher) {
        let hss_parameter = [HssParameter::new(
            LmotsAlgorithm::LmotsW2,
            LmsAlgorithm::LmsH15,
        )];
        let mut aux_data = vec![0u8; 100_000];
        let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];
        let signing_key = generate_signing_key(&hss_parameter, Some(aux_slice));

        b.iter(|| {
            let mut signing_key = signing_key.clone();
            signing_key
                .try_sign_with_aux(&MESSAGE, Some(aux_slice))
                .unwrap()
        });
    }

    #[bench]
    fn sign_h5w2_h5w2(b: &mut Bencher) {
        let hss_parameter = [
            HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
            HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
        ];
        let signing_key = generate_signing_key(&hss_parameter, None);

        b.iter(|| {
            let mut signing_key = signing_key.clone();
            signing_key.try_sign(&MESSAGE).unwrap()
        });
    }

    #[bench]
    fn sign_with_aux_h5w2_h5w2(b: &mut Bencher) {
        let hss_parameter = [
            HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
            HssParameter::new(LmotsAlgorithm::LmotsW2, LmsAlgorithm::LmsH5),
        ];
        let mut aux_data = vec![0u8; 100_000];
        let aux_slice: &mut &mut [u8] = &mut &mut aux_data[..];
        let signing_key = generate_signing_key(&hss_parameter, Some(aux_slice));

        b.iter(|| {
            let mut signing_key = signing_key.clone();
            signing_key
                .try_sign_with_aux(&MESSAGE, Some(aux_slice))
                .unwrap()
        });
    }

    #[bench]
    fn verify(b: &mut Bencher) {
        let (verifying_key, signature) = generate_verifying_key_and_signature();

        b.iter(|| {
            let _ = verifying_key.verify(&MESSAGE, &signature).is_ok();
        });
    }

    #[bench]
    fn verify_reference(b: &mut Bencher) {
        let (verifying_key, signature) = generate_verifying_key_and_signature();
        let ref_signature = VerifierSignature::from_ref(signature.as_ref()).unwrap();

        b.iter(|| {
            let _ = verifying_key.verify(&MESSAGE, &ref_signature).is_ok();
        });
    }
}

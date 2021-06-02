use crate::lm_ots::definitions::QType;
use crate::lm_ots::signing::LmotsSignature;
use crate::lms::definitions::LmsAlgorithmParameter;
use crate::lms::definitions::LmsPrivateKey;
use crate::lms::definitions::LmsPublicKey;
use crate::util::ustr::str32u;

pub struct LmsSignature {
    pub lms_parameter: LmsAlgorithmParameter,
    pub q: QType,
    pub lmots_signature: LmotsSignature,
    pub path: Vec<Vec<u8>>,
}

impl LmsSignature {
    pub fn sign(
        lms_private_key: &mut LmsPrivateKey,
        lms_public_key: &LmsPublicKey,
        message: &[u8],
    ) -> Result<LmsSignature, &'static str> {
        let lms_parameter = lms_private_key.lms_type.get_parameter();
        let lm_ots_private_key = lms_private_key.use_lmots_private_key()?;

        let ots_signature = LmotsSignature::sign(lm_ots_private_key, message);

        let h = lms_parameter.h;
        let mut i = 0usize;
        let r = 2usize.pow(h as u32) + str32u(&lm_ots_private_key.q) as usize;

        let mut path: Vec<Vec<u8>> = Vec::new();

        while i < h.into() {
            let temp = (r / (2usize.pow(i as u32))) ^ 0x1;
            path.push(lms_public_key.tree[temp].clone());
            i += 1;
        }

        let signature = LmsSignature {
            lms_parameter,
            q: lm_ots_private_key.q,
            lmots_signature: ots_signature,
            path,
        };

        Ok(signature)
    }
}

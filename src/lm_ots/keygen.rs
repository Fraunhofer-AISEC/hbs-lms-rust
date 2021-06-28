use super::definitions::*;
use super::parameter::LmotsParameter;
use crate::util::dynamic_array::DynamicArray;
use crate::{
    constants::{D_PBLC, MAX_N, MAX_P},
    util::ustr::*,
};

pub fn generate_private_key<OTS: LmotsParameter>(
    i: IType,
    q: QType,
    seed: Seed,
) -> LmotsPrivateKey<OTS> {
    let mut key = DynamicArray::new();

    let mut lmots_parameter = <OTS>::new();

    for index in 0..lmots_parameter.get_p() {
        lmots_parameter.update(&i);
        lmots_parameter.update(&q);
        lmots_parameter.update(&u16str(index as u16));
        lmots_parameter.update(&[0xff]);
        lmots_parameter.update(&seed);

        key[index as usize] = lmots_parameter.finalize_reset();
    }

    LmotsPrivateKey::new(i, q, key)
}

pub fn generate_public_key<OTS: LmotsParameter>(
    private_key: &LmotsPrivateKey<OTS>,
) -> LmotsPublicKey<OTS> {
    let mut parameter = <OTS>::new();

    let max_word_index: usize = (1 << parameter.get_w()) - 1;
    let key = &private_key.key;

    let mut y: DynamicArray<DynamicArray<u8, MAX_N>, MAX_P> = DynamicArray::new();

    for i in 0..parameter.get_p() as usize {
        let mut tmp = key[i];

        for j in 0..max_word_index {
            parameter.update(&private_key.I);
            parameter.update(&private_key.q);
            parameter.update(&u16str(i as u16));
            parameter.update(&u8str(j as u8));
            parameter.update(tmp.get_slice());

            for (index, value) in parameter.finalize_reset().into_iter().enumerate() {
                tmp[index] = value;
            }
        }

        y[i] = tmp;
    }

    parameter.update(&private_key.I);
    parameter.update(&private_key.q);
    parameter.update(&D_PBLC);

    for item in y.into_iter() {
        parameter.update(item.get_slice());
    }

    let mut public_key = DynamicArray::new();
    for (index, value) in parameter.finalize().into_iter().enumerate() {
        public_key[index] = value;
    }

    LmotsPublicKey::new(private_key.I, private_key.q, public_key)
}

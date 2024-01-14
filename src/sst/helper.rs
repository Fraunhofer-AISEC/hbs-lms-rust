// a function that provides our sub-tree top node idx within the SSTS
// subtree_num counts from  left-most = 1 to top part's "number_of_leaves"
pub fn get_subtree_node_idx(signing_entity_idx: u8, total_height: u8, top_div: u8) -> u32 {
    assert!(signing_entity_idx > 0);
    assert!(signing_entity_idx as u32 <= _get_num_leaves(top_div)); // number of nodes at that level
    assert!(top_div <= total_height);
    2u32.pow(top_div as u32) - 1 + (signing_entity_idx as u32)
}

fn get_num_leaves_in_sst(total_height: u8, top_div: u8) -> u32 {
    2u32.pow((total_height - top_div) as u32)
}

// For a subtree, depending on whole SSTS and division, get first leaf idx where leafs start with 0
pub fn get_sst_first_leaf_idx(signing_entity_idx: u8, total_height: u8, top_div: u8) -> u32 {
    assert!(signing_entity_idx > 0);
    assert!(signing_entity_idx as u32 <= _get_num_leaves(top_div)); // number of nodes at that level
    (((signing_entity_idx as u32) - 1) * get_num_leaves_in_sst(total_height, top_div)) as u32
}

// For a subtree, depending on whole SSTS and division, get last leaf idx where leafs start with 0
pub fn get_sst_last_leaf_idx(signing_entity_idx: u8, total_height: u8, top_div: u8) -> u32 {
    assert!(signing_entity_idx > 0);
    assert!(signing_entity_idx as u32 <= _get_num_leaves(top_div)); // number of nodes at that level
    get_sst_first_leaf_idx(signing_entity_idx, total_height, top_div) - 1
        + get_num_leaves_in_sst(total_height, top_div)
}

// For a subtree, depending on whole SSTS and division, get first leaf idx on whole SSTS
pub fn _get_sst_first_leaf_node_idx(signing_entity_idx: u8, total_height: u8, top_div: u8) -> u32 {
    assert!(signing_entity_idx > 0);
    assert!(signing_entity_idx as u32 <= _get_num_leaves(top_div)); // number of nodes at that level
    2u32.pow(total_height as u32)
        + (((signing_entity_idx as u32) - 1) * get_num_leaves_in_sst(total_height, top_div)) as u32
}

// For a subtree, depending on whole SSTS and division, get last leaf idx on whole SSTS
pub fn _get_sst_last_leaf_node_idx(signing_entity_idx: u8, total_height: u8, top_div: u8) -> u32 {
    assert!(signing_entity_idx > 0);
    assert!(signing_entity_idx as u32 <= _get_num_leaves(top_div)); // number of nodes at that level
    _get_sst_first_leaf_node_idx(signing_entity_idx, total_height, top_div) - 1
        + get_num_leaves_in_sst(total_height, top_div)
}

// number of leaves of a Merkle tree
fn _get_num_leaves(height: u8) -> u32 {
    2u32.pow(height as u32)
}

fn _get_last_leaf_node_idx(height: u8) -> u32 {
    2u32.pow(height as u32 + 1) - 1
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_get_subtree_node_in_ssts_1() {
        let subtree_node_idx = get_subtree_node_idx(1, 4, 2);
        assert_eq!(4, subtree_node_idx);
    }

    #[test]
    fn test_get_subtree_node_in_ssts_2() {
        let subtree_node_idx = get_subtree_node_idx(2, 4, 2);
        assert_eq!(5, subtree_node_idx);
    }

    #[test]
    fn test_get_subtree_node_in_ssts_3() {
        let subtree_node_idx = get_subtree_node_idx(1, 4, 3);
        assert_eq!(8, subtree_node_idx);
    }

    #[test]
    fn test_get_subtree_node_in_ssts_4() {
        let subtree_node_idx = get_subtree_node_idx(2, 4, 3);
        assert_eq!(9, subtree_node_idx);
    }

    #[test]
    fn test_get_subtree_node_in_ssts_5() {
        let subtree_node_idx = get_subtree_node_idx(1, 4, 4);
        assert_eq!(16, subtree_node_idx);
    }

    #[test]
    fn test_get_subtree_node_in_ssts_6() {
        let subtree_node_idx = get_subtree_node_idx(9, 4, 4);
        assert_eq!(24, subtree_node_idx);
    }

    // one outermost "leaf"
    #[test]
    fn test_get_subtree_node_in_ssts_7() {
        let subtree_node_idx = get_subtree_node_idx(16, 4, 4);
        assert_eq!(31, subtree_node_idx);
    }

    // wrong config, subtree_node_idx too high
    #[test]
    #[should_panic]
    fn test_get_subtree_node_in_ssts_8() {
        let _subtree_node_idx = get_subtree_node_idx(17, 4, 4);
    }

    #[test]
    fn test_get_last_leaf_node_idx() {
        let last_idx = _get_last_leaf_node_idx(5);
        assert_eq!(63, last_idx);
    }

    /*
    fn get_sst_first_leaf_idx(signing_entity_idx: usize, total_height: usize, top_div: usize) -> usize {
        2usize.pow(total_height as u32) - 1 + ((signing_entity_idx - 1) * 2usize.pow((total_height - top_div) as u32))
    }

    // For a subtree, depending on whole SSTS and division, get first leaf idx on whole SSTS
    fn get_sst_last_leaf_idx(signing_entity_idx: usize, total_height: usize, top_div: usize) -> usize {
        get_sst_first_leaf_idx(signing_entity_idx, total_height, top_div) - 1 + 2usize.pow((total_height - top_div) as u32)
    }
    */

    #[test]
    fn test_get_sst_first_leaf_idx_1() {
        let first_leaf_idx = _get_sst_first_leaf_node_idx(1, 5, 3);
        assert_eq!(32, first_leaf_idx);
    }

    #[test]
    fn test_get_sst_first_leaf_idx_2() {
        let first_leaf_idx = _get_sst_first_leaf_node_idx(3, 5, 3);
        assert_eq!(40, first_leaf_idx);
    }

    #[test]
    fn test_get_sst_first_leaf_idx_3() {
        let first_leaf_idx = _get_sst_first_leaf_node_idx(8, 5, 3);
        assert_eq!(60, first_leaf_idx);
    }

    #[test]
    fn test_get_sst_last_leaf_idx_1() {
        let last_leaf_idx = _get_sst_last_leaf_node_idx(1, 5, 3);
        assert_eq!(35, last_leaf_idx);
    }

    #[test]
    fn test_get_sst_last_leaf_idx_2() {
        let last_leaf_idx = _get_sst_last_leaf_node_idx(3, 5, 3);
        assert_eq!(43, last_leaf_idx);
    }

    #[test]
    fn test_get_sst_last_leaf_idx_3() {
        let last_leaf_idx = _get_sst_last_leaf_node_idx(8, 5, 3);
        assert_eq!(63, last_leaf_idx);
    }

    #[test]
    #[should_panic]
    fn test_get_sst_last_leaf_idx_4() {
        let last_leaf_idx = _get_sst_last_leaf_node_idx(9, 5, 3);
        assert_eq!(63, last_leaf_idx);
    }
}

// a function that provides our sub-tree top node idx within the SSTS
// we provide parameters index, total height and dividing (top/bottom)
// subtree_num counts from  left-most = 1 to "number_of_leaves" dep. on top division
fn get_subtree_node_idx(subtree_num: usize, tot_height: usize, top_div: usize) -> usize {
    assert!(subtree_num > 0);
    assert!(subtree_num <= get_num_leaves(top_div)); // number of nodes at that level
    assert!(top_div <= tot_height);

    2usize.pow(top_div as u32) - 1 + subtree_num
}

// how many subtrees, dep on total height and division
// -> call number_leaves(top_height)

// number of leaves of a regular Merkle tree
fn get_num_leaves(height: usize) -> usize {
    2usize.pow(height as u32)
}

// last_leaf_node_idx
// (2 ^ (height+1)) - 1



#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn sst_get_subtree_node_in_ssts_1() {
        let subtree_node_idx = get_subtree_node_idx(1, 4, 2);
        assert_eq!(4, subtree_node_idx);
    }

    #[test]
    fn sst_get_subtree_node_in_ssts_2() {
        let subtree_node_idx = get_subtree_node_idx(2, 4, 2);
        assert_eq!(5, subtree_node_idx);
    }

    #[test]
    fn sst_get_subtree_node_in_ssts_3() {
        let subtree_node_idx = get_subtree_node_idx(1, 4, 3);
        assert_eq!(8, subtree_node_idx);
    }

    #[test]
    fn sst_get_subtree_node_in_ssts_4() {
        let subtree_node_idx = get_subtree_node_idx(2, 4, 3);
        assert_eq!(9, subtree_node_idx);
    }

    #[test]
    fn sst_get_subtree_node_in_ssts_5() {
        let subtree_node_idx = get_subtree_node_idx(1, 4, 4);
        assert_eq!(16, subtree_node_idx);
    }

    #[test]
    fn sst_get_subtree_node_in_ssts_6() {
        let subtree_node_idx = get_subtree_node_idx(9, 4, 4);
        assert_eq!(24, subtree_node_idx);
    }

    // one outermost "leaf"
    #[test]
    fn sst_get_subtree_node_in_ssts_7() {
        let subtree_node_idx = get_subtree_node_idx(16, 4, 4);
        assert_eq!(31, subtree_node_idx);
    }

    // wrong config, subtree_node_idx too high
    #[test]
    #[should_panic]
    fn sst_get_subtree_node_in_ssts_8() {
        let _subtree_node_idx = get_subtree_node_idx(17, 4, 4);
        //assert_eq!(31, subtree_node_idx);
    }

}
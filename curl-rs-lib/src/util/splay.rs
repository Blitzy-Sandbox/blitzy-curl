//! Splay tree implementation for timeout scheduling.
//!
//! This module is a Rust rewrite of `lib/splay.c` (291 lines) from the C curl
//! codebase. It implements a top-down splay tree using the Sleator-Tarjan
//! algorithm, used primarily by the multi interface for timeout management.
//!
//! ## C-to-Rust Mapping
//!
//! | C Construct | Rust Replacement |
//! |---|---|
//! | `struct curltime` (tv_sec, tv_usec) | `std::time::Instant` (monotonic clock) |
//! | `struct Curl_tree` with `smaller`/`larger` pointers | `SplayNode<T>` with `Option<Box<...>>` |
//! | Circular doubly-linked list (`samen`/`samep`) | `Vec<T>` for duplicate-key payloads |
//! | `malloc`/`free` node management | Rust `Box` ownership semantics |
//! | `Curl_splay()` with raw pointer assembly | Vec-based collection with bottom-up reassembly |
//!
//! ## Safety
//!
//! This module contains **zero** `unsafe` blocks. All tree manipulation uses
//! Rust's ownership and borrowing model exclusively. The C circular linked list
//! for duplicate keys is replaced with `Vec<T>`, eliminating all raw pointer
//! manipulation.

use std::cmp::Ordering;
use std::fmt;
use std::time::Instant;

// Imported per schema requirements for error handling consistency across the crate.
// Splay tree operations are infallible (insert always succeeds, remove returns
// Option), so CurlError is not directly used in method signatures, but the import
// is retained for crate-wide error type visibility and future extensibility.
#[allow(unused_imports)]
use crate::error::CurlError;

/// The key type for splay tree nodes, used for timeout scheduling.
///
/// Replaces C `struct curltime` (with `tv_sec` and `tv_usec` fields) with Rust's
/// monotonic clock type. `Instant` implements `Ord`, providing natural comparison
/// semantics and eliminating the need for the C `Curl_splaycomparekeys` function.
pub type SplayKey = Instant;

/// Internal node of the splay tree.
///
/// Replaces C `struct Curl_tree`:
/// - `smaller`/`larger` child pointers → `left`/`right` as `Option<Box<SplayNode<T>>>`
/// - `samen`/`samep` circular list pointers → `duplicates: Vec<T>` (zero unsafe)
/// - `void *ptr` payload → generic `payload: T`
/// - `struct curltime key` → `key: SplayKey` (= `Instant`)
struct SplayNode<T> {
    /// The timeout instant this node is keyed on.
    key: SplayKey,
    /// The primary payload associated with this key.
    payload: T,
    /// Left subtree containing nodes with keys less than this node's key.
    /// Corresponds to `smaller` in the C implementation.
    left: Option<Box<SplayNode<T>>>,
    /// Right subtree containing nodes with keys greater than this node's key.
    /// Corresponds to `larger` in the C implementation.
    right: Option<Box<SplayNode<T>>>,
    /// Additional payloads sharing the exact same key.
    ///
    /// Replaces the C circular doubly-linked list (`samen`/`samep` pointers)
    /// with a safe, growable vector. In the C code, duplicate nodes were
    /// marked with `SPLAY_SUBNODE` sentinel key `{~0, -1}`; here they are
    /// simply additional elements in this vector.
    duplicates: Vec<T>,
}

impl<T> SplayNode<T> {
    /// Creates a new splay node with the given key and payload.
    fn new(key: SplayKey, payload: T) -> Self {
        SplayNode {
            key,
            payload,
            left: None,
            right: None,
            duplicates: Vec::new(),
        }
    }
}

/// A self-adjusting binary search tree for timeout scheduling.
///
/// This splay tree is the Rust equivalent of the C splay tree in `lib/splay.c`.
/// It uses the top-down splaying algorithm by Sleator and Tarjan, which amortizes
/// the cost of operations to O(log n) over sequences of accesses.
///
/// ## Usage
///
/// The primary consumer is the multi interface (`multi.rs`), which uses the splay
/// tree to efficiently manage per-transfer timeouts:
///
/// ```ignore
/// use std::time::{Duration, Instant};
/// use curl_rs_lib::util::splay::SplayTree;
///
/// let mut tree: SplayTree<u64> = SplayTree::new();
/// let now = Instant::now();
///
/// // Insert timeouts
/// tree.insert(now + Duration::from_secs(5), 1);
/// tree.insert(now + Duration::from_secs(3), 2);
///
/// // Find and remove the nearest expired timeout
/// let deadline = now + Duration::from_secs(4);
/// if let Some((key, handle_id)) = tree.get_nearest(&deadline, true) {
///     // handle_id == 2, key == now + 3s (the earliest expired timeout)
/// }
/// ```
///
/// ## Complexity
///
/// All operations have O(log n) amortized time complexity due to splaying.
/// Individual operations may be O(n) in the worst case, but any sequence of
/// m operations on a tree of n nodes takes O((m + n) log n) total time.
///
/// ## Duplicate Keys
///
/// Multiple items may share the same key (common when multiple transfers have
/// the same timeout deadline). Duplicates are stored in a `Vec<T>` on the same
/// tree node, replacing the C implementation's circular doubly-linked list
/// (`samen`/`samep` pointers) with zero unsafe code.
pub struct SplayTree<T> {
    /// The root node of the splay tree, or `None` if the tree is empty.
    root: Option<Box<SplayNode<T>>>,
    /// Total number of items in the tree, including all duplicates.
    size: usize,
}

impl<T> SplayTree<T> {
    /// Creates a new, empty splay tree.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let tree: SplayTree<i32> = SplayTree::new();
    /// assert!(tree.is_empty());
    /// assert_eq!(tree.len(), 0);
    /// ```
    pub fn new() -> Self {
        SplayTree {
            root: None,
            size: 0,
        }
    }

    /// Returns `true` if the tree contains no items.
    pub fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// Returns the total number of items stored in the tree,
    /// including all items at nodes with duplicate keys.
    pub fn len(&self) -> usize {
        self.size
    }

    /// Inserts a payload with the given key into the splay tree.
    ///
    /// If a node with the same key already exists, the payload is added to that
    /// node's duplicate list (the `Vec<T>` replacing the C circular `samen`/`samep`
    /// linked list). Otherwise, a new node is created and the tree is restructured
    /// by splitting around the splayed root.
    ///
    /// Corresponds to C `Curl_splayinsert`.
    ///
    /// # Complexity
    ///
    /// O(log n) amortized.
    pub fn insert(&mut self, key: SplayKey, payload: T) {
        self.size += 1;

        if self.root.is_none() {
            self.root = Some(Box::new(SplayNode::new(key, payload)));
            return;
        }

        // Splay the tree on the given key to bring the closest node to root.
        let root = self.root.take().unwrap();
        let mut root = Self::splay(root, &key);

        match key.cmp(&root.key) {
            Ordering::Less => {
                // New key is smaller than root: new node becomes root.
                //
                // C equivalent (Curl_splayinsert):
                //   node->smaller = t->smaller;
                //   node->larger = t;
                //   t->smaller = NULL;
                let mut new_node = Box::new(SplayNode::new(key, payload));
                new_node.left = root.left.take();
                new_node.right = Some(root);
                self.root = Some(new_node);
            }
            Ordering::Greater => {
                // New key is larger than root: new node becomes root.
                //
                // C equivalent (Curl_splayinsert):
                //   node->larger = t->larger;
                //   node->smaller = t;
                //   t->larger = NULL;
                let mut new_node = Box::new(SplayNode::new(key, payload));
                new_node.right = root.right.take();
                new_node.left = Some(root);
                self.root = Some(new_node);
            }
            Ordering::Equal => {
                // Duplicate key: add to the existing node's duplicate list.
                //
                // C equivalent: adds to circular samen/samep list and marks
                // the new node with SPLAY_SUBNODE sentinel key {~0, -1}.
                // In Rust, we simply push to the Vec.
                root.duplicates.push(payload);
                self.root = Some(root);
            }
        }
    }

    /// Removes and returns one item with the given key from the tree.
    ///
    /// If the matching node has duplicate items, one duplicate is popped from the
    /// duplicates list (O(1)). If no duplicates remain, the node itself is removed
    /// and the left and right subtrees are joined via a secondary splay.
    ///
    /// Returns `None` if no item with the given key exists.
    ///
    /// Corresponds to the key-based removal path of C `Curl_splayremove`.
    ///
    /// # Complexity
    ///
    /// O(log n) amortized.
    pub fn remove(&mut self, key: &SplayKey) -> Option<T> {
        let root = self.root.take()?;
        let mut root = Self::splay(root, key);

        if root.key != *key {
            // Key not found in the tree
            self.root = Some(root);
            return None;
        }

        self.size -= 1;

        // If duplicates exist, pop one from the list.
        // The node remains in the tree with the primary payload intact.
        if !root.duplicates.is_empty() {
            let payload = root.duplicates.pop().unwrap();
            self.root = Some(root);
            return Some(payload);
        }

        // No duplicates: remove the root node entirely.
        // Destructure to reclaim ownership of all fields.
        let node = *root;
        let SplayNode {
            payload,
            left,
            right,
            key: removed_key,
            duplicates: _,
        } = node;

        // Join the left and right subtrees into a single tree.
        // C equivalent: splay(removenode->key, t->smaller), then x->larger = t->larger
        self.root = Self::join_subtrees(left, right, &removed_key);
        Some(payload)
    }

    /// Removes and returns a specific item matching the predicate at the given key.
    ///
    /// This is the Rust equivalent of C `Curl_splayremove` with a specific node
    /// pointer argument. Since Rust doesn't expose raw node pointers, a predicate
    /// function identifies the target item among potential duplicates.
    ///
    /// The search order is:
    /// 1. **Duplicate items** are checked first — removing a duplicate is the
    ///    cheapest path (no tree restructuring, O(1) via `swap_remove`).
    /// 2. **Primary payload** is checked last. If it matches and duplicates exist,
    ///    a duplicate is promoted to primary. If no duplicates exist, the node is
    ///    removed entirely and subtrees are joined.
    ///
    /// Returns `None` if no item at the given key satisfies the predicate.
    ///
    /// # Complexity
    ///
    /// O(log n) amortized for the splay, plus O(d) for scanning d duplicates.
    pub fn remove_by_ref(
        &mut self,
        key: &SplayKey,
        predicate: impl Fn(&T) -> bool,
    ) -> Option<T> {
        let root = self.root.take()?;
        let mut root = Self::splay(root, key);

        if root.key != *key {
            // Key not found in tree
            self.root = Some(root);
            return None;
        }

        // First scan duplicates for a match (cheapest removal — no restructuring).
        if let Some(pos) = root.duplicates.iter().position(&predicate) {
            let payload = root.duplicates.swap_remove(pos);
            self.root = Some(root);
            self.size -= 1;
            return Some(payload);
        }

        // Check the primary payload.
        if !predicate(&root.payload) {
            // No match found among primary or duplicates
            self.root = Some(root);
            return None;
        }

        self.size -= 1;

        if root.duplicates.is_empty() {
            // Remove root entirely: join left and right subtrees.
            //
            // C equivalent: the else branch at the bottom of Curl_splayremove
            // where t->samen == t (no duplicates).
            let node = *root;
            let SplayNode {
                payload,
                left,
                right,
                key: removed_key,
                duplicates: _,
            } = node;
            self.root = Self::join_subtrees(left, right, &removed_key);
            return Some(payload);
        }

        // Promote a duplicate to become the primary payload.
        //
        // C equivalent: the branch in Curl_splayremove where t->samen != t:
        //   x = t->samen;         (pick a same-key node)
        //   x->key = t->key;      (copy key)
        //   x->smaller = t->smaller; x->larger = t->larger; (copy tree links)
        //   <re-link circular list>
        //
        // In Rust, we simply swap the primary payload with the last duplicate.
        let promoted = root.duplicates.pop().unwrap();
        let old_payload = std::mem::replace(&mut root.payload, promoted);
        self.root = Some(root);
        Some(old_payload)
    }

    /// Finds the nearest item with a key less than or equal to the given key.
    ///
    /// Corresponds to C `Curl_splaygetbest`. This is the primary method used by
    /// the multi interface to find expired timeouts: the caller passes "now" as
    /// the key and gets back the earliest timeout that has already expired (or
    /// is due right now).
    ///
    /// After splaying on `key`, the root holds the closest node. If the root's key
    /// is ≤ `key` (meaning the timeout has expired), it is returned and optionally
    /// removed.
    ///
    /// # Arguments
    ///
    /// * `key` — The reference time point (typically "now") to compare against.
    /// * `remove` — If `true`, the matching item is removed from the tree and
    ///   returned as `Some((found_key, payload))`. If `false`, the tree is splayed
    ///   for rebalancing but no item is removed; returns `None` since we cannot
    ///   return an owned `T` without removing it.
    ///
    /// # Returns
    ///
    /// * `Some((found_key, payload))` if a node with `found_key <= key` exists
    ///   and `remove` is `true`.
    /// * `None` if no such node exists, or if `remove` is `false` (splay-only mode).
    ///
    /// # Complexity
    ///
    /// O(log n) amortized.
    pub fn get_nearest(
        &mut self,
        key: &SplayKey,
        remove: bool,
    ) -> Option<(SplayKey, T)> {
        let root = self.root.take()?;
        let mut root = Self::splay(root, key);

        // After splaying on `key`, the root holds the closest node.
        // Check if root's key is ≤ the given key (i.e., the timeout has expired).
        if root.key > *key {
            // Root is strictly past the deadline — no expired timeout found.
            self.root = Some(root);
            return None;
        }

        if !remove {
            // Splay performed for rebalancing, but caller opted out of removal.
            // We cannot return an owned T without removing it from the tree.
            self.root = Some(root);
            return None;
        }

        // Remove the nearest expired item.
        let result_key = root.key;
        self.size -= 1;

        // If duplicates exist, pop one from the list. The node remains in the tree.
        if !root.duplicates.is_empty() {
            let payload = root.duplicates.pop().unwrap();
            self.root = Some(root);
            return Some((result_key, payload));
        }

        // Remove root entirely and join subtrees.
        let node = *root;
        let SplayNode {
            payload,
            left,
            right,
            key: removed_key,
            duplicates: _,
        } = node;

        self.root = Self::join_subtrees(left, right, &removed_key);
        Some((removed_key, payload))
    }

    /// Returns a reference to the minimum key in the tree without modifying it.
    ///
    /// Walks the left spine of the tree to find the smallest key. This is useful
    /// for checking the next timeout deadline without performing a splay operation
    /// (which would restructure the tree).
    ///
    /// # Complexity
    ///
    /// O(depth of left spine), which is O(log n) amortized after recent splay
    /// operations, but O(n) worst case for a degenerate tree.
    pub fn peek_min(&self) -> Option<&SplayKey> {
        let mut current = self.root.as_ref()?;
        while let Some(ref left) = current.left {
            current = left;
        }
        Some(&current.key)
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    /// Top-down splay operation (Sleator-Tarjan algorithm).
    ///
    /// Takes ownership of the root node, splays on the given key, and returns
    /// the new root. After splaying, the node with the key closest to the target
    /// is at the root position.
    ///
    /// ## C-to-Rust Translation
    ///
    /// The C `Curl_splay()` uses a temporary header node `N` with `N.smaller`
    /// and `N.larger` as assembly tree roots, plus `l` and `r` raw pointers
    /// tracking the rightmost/leftmost nodes of the left/right assembly trees.
    ///
    /// In Rust, we replace raw pointer tracking with two vectors:
    /// - `left_chain`: nodes linked to the left assembly tree (via "link left"
    ///   operations), collected in order. Each node's `right` child was taken
    ///   during linking; during assembly, nodes are chained through `right`.
    /// - `right_chain`: nodes linked to the right assembly tree (via "link right"
    ///   operations), collected in order. Each node's `left` child was taken
    ///   during linking; during assembly, nodes are chained through `left`.
    ///
    /// ## Zig-Zig Optimization
    ///
    /// When two consecutive comparisons go in the same direction (e.g., both left),
    /// a rotation is performed before linking. This reduces the tree depth and is
    /// the key optimization that gives splay trees their amortized O(log n) bound.
    fn splay(mut current: Box<SplayNode<T>>, key: &SplayKey) -> Box<SplayNode<T>> {
        // Nodes displaced to the left assembly tree.
        // During "link left" operations, we descend right and link the current
        // node into the left assembly. During assembly, these nodes are chained
        // through their `right` pointers to form the final root's left subtree.
        let mut left_chain: Vec<Box<SplayNode<T>>> = Vec::new();

        // Nodes displaced to the right assembly tree.
        // During "link right" operations, we descend left and link the current
        // node into the right assembly. During assembly, these nodes are chained
        // through their `left` pointers to form the final root's right subtree.
        let mut right_chain: Vec<Box<SplayNode<T>>> = Vec::new();

        loop {
            match key.cmp(&current.key) {
                Ordering::Less => {
                    // Target is in the left subtree.
                    if current.left.is_none() {
                        break;
                    }

                    // Check for zig-zig: target is also less than the left child's
                    // key, and the left child has a left child to rotate with.
                    //
                    // C equivalent:
                    //   if(compare(i, t->smaller->key) < 0) {
                    //       y = t->smaller; t->smaller = y->larger;
                    //       y->larger = t; t = y;
                    //   }
                    let do_zig_zig = {
                        let left = current.left.as_ref().unwrap();
                        *key < left.key && left.left.is_some()
                    };

                    if do_zig_zig {
                        // Rotate right before linking to reduce depth:
                        //
                        //     current            y
                        //     /     \           /   \
                        //    y       C   →    A     current
                        //   / \                     /     \
                        //  A   B                   B       C
                        //
                        let mut y = current.left.take().unwrap();
                        current.left = y.right.take();
                        y.right = Some(current);
                        current = y;

                        // After rotation, current is the old left child.
                        // If current has no left child, we can't descend further.
                        if current.left.is_none() {
                            break;
                        }
                    }

                    // Link right: current goes to right assembly, descend to left child.
                    //
                    // C equivalent:
                    //   r->smaller = t; r = t; t = t->smaller;
                    let next = current.left.take().unwrap();
                    right_chain.push(current);
                    current = next;
                }

                Ordering::Greater => {
                    // Target is in the right subtree.
                    if current.right.is_none() {
                        break;
                    }

                    // Check for zig-zig: target is also greater than the right
                    // child's key, and the right child has a right child.
                    //
                    // C equivalent:
                    //   if(compare(i, t->larger->key) > 0) {
                    //       y = t->larger; t->larger = y->smaller;
                    //       y->smaller = t; t = y;
                    //   }
                    let do_zig_zig = {
                        let right = current.right.as_ref().unwrap();
                        *key > right.key && right.right.is_some()
                    };

                    if do_zig_zig {
                        // Rotate left before linking to reduce depth:
                        //
                        //   current                y
                        //   /     \              /   \
                        //  A       y    →   current   C
                        //         / \       /     \
                        //        B   C     A       B
                        //
                        let mut y = current.right.take().unwrap();
                        current.right = y.left.take();
                        y.left = Some(current);
                        current = y;

                        // After rotation, if no right child, stop.
                        if current.right.is_none() {
                            break;
                        }
                    }

                    // Link left: current goes to left assembly, descend to right child.
                    //
                    // C equivalent:
                    //   l->larger = t; l = t; t = t->larger;
                    let next = current.right.take().unwrap();
                    left_chain.push(current);
                    current = next;
                }

                Ordering::Equal => {
                    // Found exact match at current — stop splaying.
                    break;
                }
            }
        }

        // ---- Assembly phase ----
        //
        // Corresponds to C:
        //   l->larger  = t->smaller;   (last left-linked node's right = root's left)
        //   r->smaller = t->larger;    (last right-linked node's left = root's right)
        //   t->smaller = N.larger;     (root's left = first left-linked node)
        //   t->larger  = N.smaller;    (root's right = first right-linked node)
        //
        // We build the subtrees bottom-up by iterating the chains in reverse.

        // Build left subtree: chain left_chain nodes through their right pointers.
        // The innermost (last-linked) node's right child becomes current's
        // original left child.
        let mut left_subtree = current.left.take();
        for mut node in left_chain.into_iter().rev() {
            node.right = left_subtree;
            left_subtree = Some(node);
        }
        current.left = left_subtree;

        // Build right subtree: chain right_chain nodes through their left pointers.
        // The innermost (last-linked) node's left child becomes current's
        // original right child.
        let mut right_subtree = current.right.take();
        for mut node in right_chain.into_iter().rev() {
            node.left = right_subtree;
            right_subtree = Some(node);
        }
        current.right = right_subtree;

        current
    }

    /// Joins left and right subtrees after root removal.
    ///
    /// When a root node is removed, its left and right subtrees must be merged
    /// into a single tree. This is done by splaying the left subtree on the
    /// removed key, which brings the maximum of the left subtree to its root
    /// (because the removed key is larger than all left subtree keys). The
    /// maximum then has no right child, so the right subtree is attached there.
    ///
    /// Corresponds to the subtree joining logic in C `Curl_splayremove`:
    /// ```c
    /// x = Curl_splay(removenode->key, t->smaller);
    /// x->larger = t->larger;
    /// ```
    fn join_subtrees(
        left: Option<Box<SplayNode<T>>>,
        right: Option<Box<SplayNode<T>>>,
        key: &SplayKey,
    ) -> Option<Box<SplayNode<T>>> {
        match left {
            None => {
                // No left subtree: the right subtree becomes the new tree.
                // C equivalent: if(!t->smaller) x = t->larger;
                right
            }
            Some(left_tree) => {
                // Splay the left subtree on the removed key. Since all keys
                // in the left tree are strictly less than the removed key,
                // this brings the maximum to the root with no right child.
                let mut new_root = Self::splay(left_tree, key);
                // Attach the right subtree as the new root's right child.
                new_root.right = right;
                Some(new_root)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Trait implementations
// ---------------------------------------------------------------------------

impl<T> Default for SplayTree<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: fmt::Debug> fmt::Debug for SplayTree<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// Helper to recursively format a splay node and its subtrees.
        fn fmt_node<T: fmt::Debug>(
            node: &Option<Box<SplayNode<T>>>,
            f: &mut fmt::Formatter<'_>,
            indent: usize,
        ) -> fmt::Result {
            match node {
                None => {
                    write!(f, "{:indent$}(empty)", "", indent = indent)
                }
                Some(n) => {
                    write!(
                        f,
                        "{:indent$}Node(key={:?}, payload={:?}",
                        "",
                        n.key,
                        n.payload,
                        indent = indent
                    )?;
                    if !n.duplicates.is_empty() {
                        write!(f, ", duplicates={:?}", n.duplicates)?;
                    }
                    writeln!(f, ")")?;
                    if n.left.is_some() || n.right.is_some() {
                        write!(f, "{:indent$}  L: ", "", indent = indent)?;
                        fmt_node(&n.left, f, indent + 4)?;
                        writeln!(f)?;
                        write!(f, "{:indent$}  R: ", "", indent = indent)?;
                        fmt_node(&n.right, f, indent + 4)?;
                    }
                    Ok(())
                }
            }
        }

        writeln!(f, "SplayTree(size={})", self.size)?;
        fmt_node(&self.root, f, 2)
    }
}

/// Custom `Drop` implementation to prevent stack overflow on deeply nested trees.
///
/// Without this, dropping a degenerate splay tree (e.g., a long left or right
/// chain of O(n) nodes) would cause recursive `Drop` calls that overflow the
/// stack. This implementation iteratively flattens the tree using an explicit
/// stack on the heap.
impl<T> Drop for SplayTree<T> {
    fn drop(&mut self) {
        let mut stack: Vec<Box<SplayNode<T>>> = Vec::new();
        if let Some(root) = self.root.take() {
            stack.push(root);
        }
        while let Some(mut node) = stack.pop() {
            // Take children before the node drops, pushing them for processing.
            if let Some(left) = node.left.take() {
                stack.push(left);
            }
            if let Some(right) = node.right.take() {
                stack.push(right);
            }
            // `node` (with payload and duplicates Vec) drops here safely.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Helper to create a SplayKey at a fixed offset from a base instant.
    fn key_at(base: Instant, millis: u64) -> SplayKey {
        base + Duration::from_millis(millis)
    }

    #[test]
    fn test_new_tree_is_empty() {
        let tree: SplayTree<i32> = SplayTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
    }

    #[test]
    fn test_insert_single() {
        let mut tree = SplayTree::new();
        let now = Instant::now();
        tree.insert(now, 42);
        assert!(!tree.is_empty());
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_insert_multiple_distinct_keys() {
        let mut tree = SplayTree::new();
        let base = Instant::now();

        tree.insert(key_at(base, 100), 1);
        tree.insert(key_at(base, 50), 2);
        tree.insert(key_at(base, 200), 3);
        tree.insert(key_at(base, 25), 4);
        tree.insert(key_at(base, 150), 5);

        assert_eq!(tree.len(), 5);
        assert!(!tree.is_empty());
    }

    #[test]
    fn test_insert_duplicate_keys() {
        let mut tree = SplayTree::new();
        let base = Instant::now();
        let key = key_at(base, 100);

        tree.insert(key, 1);
        tree.insert(key, 2);
        tree.insert(key, 3);

        assert_eq!(tree.len(), 3);
    }

    #[test]
    fn test_remove_from_empty_tree() {
        let mut tree: SplayTree<i32> = SplayTree::new();
        let now = Instant::now();
        assert!(tree.remove(&now).is_none());
    }

    #[test]
    fn test_remove_nonexistent_key() {
        let mut tree = SplayTree::new();
        let base = Instant::now();
        tree.insert(key_at(base, 100), 1);

        assert!(tree.remove(&key_at(base, 200)).is_none());
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_remove_single_item() {
        let mut tree = SplayTree::new();
        let base = Instant::now();
        let key = key_at(base, 100);

        tree.insert(key, 42);
        let removed = tree.remove(&key);
        assert_eq!(removed, Some(42));
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
    }

    #[test]
    fn test_remove_with_duplicates() {
        let mut tree = SplayTree::new();
        let base = Instant::now();
        let key = key_at(base, 100);

        tree.insert(key, 1);
        tree.insert(key, 2);
        tree.insert(key, 3);
        assert_eq!(tree.len(), 3);

        // Remove one duplicate
        let removed = tree.remove(&key);
        assert!(removed.is_some());
        assert_eq!(tree.len(), 2);

        // Remove another
        let removed = tree.remove(&key);
        assert!(removed.is_some());
        assert_eq!(tree.len(), 1);

        // Remove last item
        let removed = tree.remove(&key);
        assert!(removed.is_some());
        assert!(tree.is_empty());

        // Tree is now empty
        assert!(tree.remove(&key).is_none());
    }

    #[test]
    fn test_remove_preserves_other_nodes() {
        let mut tree = SplayTree::new();
        let base = Instant::now();

        tree.insert(key_at(base, 100), 1);
        tree.insert(key_at(base, 50), 2);
        tree.insert(key_at(base, 200), 3);

        // Remove the middle key
        let removed = tree.remove(&key_at(base, 100));
        assert_eq!(removed, Some(1));
        assert_eq!(tree.len(), 2);

        // Other keys should still be findable
        let removed = tree.remove(&key_at(base, 50));
        assert_eq!(removed, Some(2));
        let removed = tree.remove(&key_at(base, 200));
        assert_eq!(removed, Some(3));
        assert!(tree.is_empty());
    }

    #[test]
    fn test_remove_by_ref_basic() {
        let mut tree = SplayTree::new();
        let base = Instant::now();
        let key = key_at(base, 100);

        tree.insert(key, 42);

        // Predicate matches
        let removed = tree.remove_by_ref(&key, |&v| v == 42);
        assert_eq!(removed, Some(42));
        assert!(tree.is_empty());
    }

    #[test]
    fn test_remove_by_ref_no_match() {
        let mut tree = SplayTree::new();
        let base = Instant::now();
        let key = key_at(base, 100);

        tree.insert(key, 42);

        // Predicate does not match
        let removed = tree.remove_by_ref(&key, |&v| v == 99);
        assert!(removed.is_none());
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_remove_by_ref_among_duplicates() {
        let mut tree = SplayTree::new();
        let base = Instant::now();
        let key = key_at(base, 100);

        tree.insert(key, 10);
        tree.insert(key, 20);
        tree.insert(key, 30);

        // Remove specific duplicate
        let removed = tree.remove_by_ref(&key, |&v| v == 20);
        assert_eq!(removed, Some(20));
        assert_eq!(tree.len(), 2);

        // Remove primary (value 10)
        let removed = tree.remove_by_ref(&key, |&v| v == 10);
        assert_eq!(removed, Some(10));
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_remove_by_ref_wrong_key() {
        let mut tree = SplayTree::new();
        let base = Instant::now();

        tree.insert(key_at(base, 100), 42);

        let removed = tree.remove_by_ref(&key_at(base, 200), |&v| v == 42);
        assert!(removed.is_none());
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_get_nearest_empty_tree() {
        let mut tree: SplayTree<i32> = SplayTree::new();
        let now = Instant::now();
        assert!(tree.get_nearest(&now, true).is_none());
    }

    #[test]
    fn test_get_nearest_no_expired() {
        let mut tree = SplayTree::new();
        let base = Instant::now();

        // Insert a timeout far in the future
        tree.insert(key_at(base, 10000), 1);

        // "now" is before the timeout — nothing expired
        let result = tree.get_nearest(&key_at(base, 100), true);
        assert!(result.is_none());
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_get_nearest_with_expired() {
        let mut tree = SplayTree::new();
        let base = Instant::now();

        tree.insert(key_at(base, 100), 1);
        tree.insert(key_at(base, 200), 2);
        tree.insert(key_at(base, 300), 3);

        // "now" is at 250ms — timeouts at 100 and 200 have expired
        let result = tree.get_nearest(&key_at(base, 250), true);
        assert!(result.is_some());
        let (found_key, _payload) = result.unwrap();
        // The splay brings the closest to 250 to root; since 200 <= 250, it should match
        assert!(found_key <= key_at(base, 250));

        assert_eq!(tree.len(), 2);
    }

    #[test]
    fn test_get_nearest_exact_match() {
        let mut tree = SplayTree::new();
        let base = Instant::now();
        let key = key_at(base, 100);

        tree.insert(key, 42);

        let result = tree.get_nearest(&key, true);
        assert_eq!(result, Some((key, 42)));
        assert!(tree.is_empty());
    }

    #[test]
    fn test_get_nearest_no_remove() {
        let mut tree = SplayTree::new();
        let base = Instant::now();
        let key = key_at(base, 100);

        tree.insert(key, 42);

        // remove=false: splay but don't remove — returns None
        let result = tree.get_nearest(&key, false);
        assert!(result.is_none());
        // Item should still be in the tree
        assert_eq!(tree.len(), 1);
    }

    #[test]
    fn test_get_nearest_with_duplicates() {
        let mut tree = SplayTree::new();
        let base = Instant::now();
        let key = key_at(base, 100);

        tree.insert(key, 1);
        tree.insert(key, 2);

        // Get nearest should return one of the duplicates
        let result = tree.get_nearest(&key, true);
        assert!(result.is_some());
        assert_eq!(tree.len(), 1);

        // Get the remaining one
        let result = tree.get_nearest(&key, true);
        assert!(result.is_some());
        assert!(tree.is_empty());
    }

    #[test]
    fn test_peek_min_empty() {
        let tree: SplayTree<i32> = SplayTree::new();
        assert!(tree.peek_min().is_none());
    }

    #[test]
    fn test_peek_min_single() {
        let mut tree = SplayTree::new();
        let now = Instant::now();
        tree.insert(now, 42);
        assert_eq!(tree.peek_min(), Some(&now));
    }

    #[test]
    fn test_peek_min_multiple() {
        let mut tree = SplayTree::new();
        let base = Instant::now();
        let k1 = key_at(base, 300);
        let k2 = key_at(base, 100);
        let k3 = key_at(base, 200);

        tree.insert(k1, 1);
        tree.insert(k2, 2);
        tree.insert(k3, 3);

        assert_eq!(tree.peek_min(), Some(&k2)); // 100ms is the minimum
    }

    #[test]
    fn test_peek_min_does_not_modify_tree() {
        let mut tree = SplayTree::new();
        let base = Instant::now();

        tree.insert(key_at(base, 300), 1);
        tree.insert(key_at(base, 100), 2);
        tree.insert(key_at(base, 200), 3);

        // Peek multiple times — should always return the same min
        let min1 = tree.peek_min().copied();
        let min2 = tree.peek_min().copied();
        assert_eq!(min1, min2);
        assert_eq!(tree.len(), 3);
    }

    #[test]
    fn test_default_trait() {
        let tree: SplayTree<i32> = SplayTree::default();
        assert!(tree.is_empty());
        assert_eq!(tree.len(), 0);
    }

    #[test]
    fn test_many_inserts_and_removes() {
        let mut tree = SplayTree::new();
        let base = Instant::now();

        // Insert 100 items
        for i in 0..100u64 {
            tree.insert(key_at(base, i * 10), i as i32);
        }
        assert_eq!(tree.len(), 100);

        // Remove all by key
        for i in 0..100u64 {
            let removed = tree.remove(&key_at(base, i * 10));
            assert_eq!(removed, Some(i as i32));
        }
        assert!(tree.is_empty());
    }

    #[test]
    fn test_bst_property_after_operations() {
        // Verify the BST property holds by inserting various keys
        // and then extracting all items via get_nearest.
        let mut tree = SplayTree::new();
        let base = Instant::now();

        let keys_ms: Vec<u64> = vec![50, 30, 70, 10, 40, 60, 90, 5, 20, 35];
        for &ms in &keys_ms {
            tree.insert(key_at(base, ms), ms as i32);
        }
        assert_eq!(tree.len(), keys_ms.len());

        // Extract all items via get_nearest with a far-future deadline.
        // After splaying on a key larger than all nodes, the closest (largest)
        // node is at root each time. So items come out in non-increasing order.
        let far_future = key_at(base, 100_000);
        let mut extracted = Vec::new();
        while let Some((k, v)) = tree.get_nearest(&far_future, true) {
            extracted.push((k, v));
        }

        // Verify all items were extracted
        assert_eq!(extracted.len(), keys_ms.len());
        assert!(tree.is_empty());

        // Verify the extracted keys are in non-increasing order:
        // get_nearest with far-future splays the maximum to root each time.
        for window in extracted.windows(2) {
            assert!(
                window[0].0 >= window[1].0,
                "Expected non-increasing order: {:?} should be >= {:?}",
                window[0].0,
                window[1].0
            );
        }

        // Also verify all original keys are present in the extracted set
        let mut extracted_values: Vec<i32> = extracted.iter().map(|&(_, v)| v).collect();
        extracted_values.sort();
        let mut expected_values: Vec<i32> = keys_ms.iter().map(|&ms| ms as i32).collect();
        expected_values.sort();
        assert_eq!(extracted_values, expected_values);
    }

    #[test]
    fn test_debug_format() {
        let mut tree = SplayTree::new();
        let base = Instant::now();
        tree.insert(key_at(base, 100), 42);
        let debug_str = format!("{:?}", tree);
        assert!(debug_str.contains("SplayTree"));
        assert!(debug_str.contains("42"));
    }

    #[test]
    fn test_mixed_operations() {
        let mut tree = SplayTree::new();
        let base = Instant::now();

        // Insert, remove, insert pattern
        tree.insert(key_at(base, 100), 1);
        tree.insert(key_at(base, 200), 2);
        tree.remove(&key_at(base, 100));
        tree.insert(key_at(base, 50), 3);
        tree.insert(key_at(base, 200), 4); // duplicate

        assert_eq!(tree.len(), 3);

        // Verify minimum
        assert_eq!(tree.peek_min(), Some(&key_at(base, 50)));

        // Get nearest expired (all keys <= 200)
        let result = tree.get_nearest(&key_at(base, 200), true);
        assert!(result.is_some());
        assert_eq!(tree.len(), 2);
    }
}
